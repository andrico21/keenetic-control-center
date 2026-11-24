//! kcc's own OAuth 2.1 authorization server ("sign in with kcc") for MCP clients.
//!
//! [`OAuthServer`] holds what the protocol routes share: the issuer, the registered
//! clients, the pending authorization requests and codes, the grants and the signing key.
//! The routes outside `/ui` carry no cookie authority (no session, no CSRF):
//! `GET /.well-known/oauth-authorization-server` (RFC 8414), `GET /oauth/authorize`,
//! `POST /oauth/token`, `POST /oauth/register` (RFC 7591, public clients only),
//! `POST /oauth/revoke` (RFC 7009) and `GET /oauth/jwks`. The browser steps (the consent
//! page and its approve and deny) live under `/ui` with the session and CSRF rules of
//! every page.
//!
//! Every route answers 404 until `kcc serve` activates the server with the resources of
//! the listeners that sign in with kcc ([`OAuthServer::activate`]).

extern crate alloc;

pub(crate) mod authorize;
mod codes;
mod limiter;
pub mod metadata;
mod register;
mod token;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use core::{fmt, time::Duration};
use std::sync::{OnceLock, PoisonError, RwLock};

use axum::{
    Router,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse as _, Response},
    routing::{get, post},
};
use kcc_app::{
    accounts::Clock,
    mcp_auth::{
        clients::{ClientStore, RegistrationLimiter},
        grants::GrantStore,
        pending::PendingStore,
        signing::{SigningError, SigningKey},
    },
    persist::StateStore,
    secrets::MasterKey,
    settings::Config,
};
use serde_json::json;
use url::form_urlencoded;

use self::{codes::Consented, limiter::AuthorizeLimiter};
use crate::{WebState, admin::issuer::Issuer};

/// What the listeners that sign in with kcc accept, as `kcc serve` last activated it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Activation {
    /// Every MCP resource URL a token may be issued for: each such listener's canonical
    /// resource and its aliases.
    pub resources: BTreeSet<String>,
    /// The access tokens' lifetime.
    pub access_ttl: Duration,
    /// The refresh tokens' lifetime.
    pub refresh_ttl: Duration,
}

impl Activation {
    /// The resources `resources` with the token lifetimes `(access_ttl, refresh_ttl)`.
    #[inline]
    #[must_use]
    pub const fn new(
        resources: BTreeSet<String>,
        (access_ttl, refresh_ttl): (Duration, Duration),
    ) -> Self {
        Self {
            resources,
            access_ttl,
            refresh_ttl,
        }
    }
}

/// The authorization server while active.
pub(crate) struct Active {
    /// The accepted resources.
    resources: BTreeSet<String>,
    /// The access tokens' lifetime.
    access_ttl: Duration,
    /// The grants, with the refresh tokens' lifetime.
    grants: GrantStore,
}

impl Active {
    /// Whether a token may be issued for `resource`.
    pub(crate) fn accepts(&self, resource: &str) -> bool {
        self.resources.contains(resource)
    }
}

/// kcc's authorization server.
pub struct OAuthServer {
    /// The issuer: `web.public_url` with a DNS host, else the loopback main listener as
    /// `localhost`.
    issuer: String,
    /// The state directory.
    state: StateStore,
    /// Seals the signing key.
    key: MasterKey,
    /// Shared with the accounts and the audit.
    clock: Arc<dyn Clock>,
    /// The signing key, loaded (or created) on first use.
    signing: OnceLock<SigningKey>,
    /// The registered clients.
    clients: ClientStore,
    /// Pending authorization requests and issued codes, in memory.
    pending: PendingStore,
    /// Registrations per address.
    registrations: RegistrationLimiter,
    /// Authorization requests per address.
    authorizations: AuthorizeLimiter,
    /// The password each issued code was consented with.
    consented: Consented,
    /// The listeners' resources and the grant store; `None` while no listener uses kcc.
    active: RwLock<Option<Arc<Active>>>,
}

impl fmt::Debug for OAuthServer {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthServer")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl OAuthServer {
    /// The authorization server of `config` over `state`, its signing key sealed under
    /// `key`; `None` when `config` gives it no issuer (the Web UI is off, or the main
    /// listener has neither a DNS public URL nor a loopback address).
    #[inline]
    #[must_use]
    pub fn of(
        config: &Config,
        (state, key): (StateStore, MasterKey),
        clock: Arc<dyn Clock>,
    ) -> Option<Self> {
        let Issuer::Url(issuer) = Issuer::of(config) else {
            return None;
        };
        Some(Self {
            issuer,
            clients: ClientStore::new(state.clone(), Arc::clone(&clock)),
            pending: PendingStore::new(Arc::clone(&clock)),
            registrations: RegistrationLimiter::new(Arc::clone(&clock)),
            authorizations: AuthorizeLimiter::new(Arc::clone(&clock)),
            consented: Consented::default(),
            state,
            key,
            clock,
            signing: OnceLock::new(),
            active: RwLock::new(None),
        })
    }

    /// The issuer.
    #[inline]
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The signing key, created and sealed on first use. Blocking.
    ///
    /// # Errors
    ///
    /// [`SigningError`] when the sealed key cannot be read, opened or created.
    #[inline]
    pub fn signing_key(&self) -> Result<&SigningKey, SigningError> {
        if let Some(key) = self.signing.get() {
            return Ok(key);
        }
        let loaded = SigningKey::load_or_create(&self.state, &self.key)?;
        Ok(self.signing.get_or_init(|| loaded))
    }

    /// Turns the server on for `activation`, or off with `None`: the routes then answer
    /// 404 and every resource is unknown.
    #[inline]
    pub fn activate(&self, activation: Option<Activation>) {
        let next = activation.map(|wanted| {
            Arc::new(Active {
                grants: GrantStore::new(
                    self.state.clone(),
                    Arc::clone(&self.clock),
                    wanted.refresh_ttl,
                ),
                resources: wanted.resources,
                access_ttl: wanted.access_ttl,
            })
        });
        *self.active.write().unwrap_or_else(PoisonError::into_inner) = next;
    }

    /// The server while active.
    pub(crate) fn active(&self) -> Option<Arc<Active>> {
        self.active
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether `id` names a live pending authorization request while the server is on.
    pub(crate) fn is_live_request(&self, id: &str) -> bool {
        self.active().is_some() && self.pending.peek(id).is_some()
    }

    /// The current Unix second.
    pub(crate) fn now(&self) -> u64 {
        self.clock.unix_seconds()
    }

    /// The registered clients.
    pub(crate) const fn clients(&self) -> &ClientStore {
        &self.clients
    }

    /// The pending requests and codes.
    pub(crate) const fn pending(&self) -> &PendingStore {
        &self.pending
    }

    /// The consenting passwords of issued codes.
    pub(crate) const fn consented(&self) -> &Consented {
        &self.consented
    }
}

/// The protocol routes, outside `/ui`: no session, no CSRF.
pub(crate) fn routes() -> Router<WebState> {
    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata::document),
        )
        .route(
            "/.well-known/oauth-authorization-server/{*path}",
            get(metadata::document_at),
        )
        .route("/oauth/jwks", get(metadata::jwks))
        .route("/oauth/authorize", get(authorize::authorize))
        .route("/oauth/token", post(token::token))
        .route("/oauth/register", post(register::register))
        .route("/oauth/revoke", post(register::revoke))
}

/// Answers a refused protocol request as the token endpoint answers every refusal.
///
/// A `413` (body limit) or `405` (method; axum adds its `Allow` header outside every
/// layer) on an `/oauth/` path becomes `invalid_request`, never stored or cached.
// cancel-safe: only maps the inner response.
pub(crate) async fn plain_errors(request: Request, next: Next) -> Response {
    let protocol = request.uri().path().starts_with("/oauth/");
    let response = next.run(request).await;
    let status = response.status();
    if !protocol
        || !matches!(
            status,
            StatusCode::PAYLOAD_TOO_LARGE | StatusCode::METHOD_NOT_ALLOWED
        )
    {
        return response;
    }
    token::no_store(status, json!({"error": "invalid_request"}))
}

/// The active server of `state`; `None` while there is none (every route answers 404).
pub(crate) fn serving(state: &WebState) -> Option<(Arc<OAuthServer>, Arc<Active>)> {
    let server = state.oauth()?;
    let active = server.active()?;
    Some((server, active))
}

/// The `404` of an OAuth route while no listener signs in with kcc.
pub(crate) fn absent() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// The parameters of a query or form body; `None` when one is given twice (RFC 6749
/// section 3.1). A parameter without a value counts as absent.
pub(crate) fn single_params(text: &str) -> Option<BTreeMap<String, String>> {
    let mut params = BTreeMap::new();
    for (name, value) in form_urlencoded::parse(text.as_bytes()) {
        if value.is_empty() {
            continue;
        }
        if params
            .insert(name.into_owned(), value.into_owned())
            .is_some()
        {
            return None;
        }
    }
    Some(params)
}
