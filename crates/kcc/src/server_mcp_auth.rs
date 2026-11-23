//! kcc sign-in for the MCP listeners with `oauth = "kcc"`.
//!
//! The kit validates kcc's tokens through its normal OAuth path: issuer = kcc's issuer,
//! `jwks_uri = http://localhost:<port>/jwks` on the internal loopback listener ([`jwks`];
//! plain HTTP, admitted by `allow_http_oauth_urls` and the `localhost` SSRF allowlist
//! entry), `EdDSA` only, a subject required, the audience the listener's canonical MCP
//! resource with its aliases. The scope `mcp` maps to the reserved role `kcc-account`;
//! `kcc-mcp` then resolves the account's current role on every call through
//! [`principals::FilePrincipals`].

extern crate alloc;

pub(crate) mod jwks;
pub(crate) mod principals;
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions are not rendered API documentation"
)]
mod tests;

use alloc::{collections::BTreeSet, sync::Arc};
use core::{iter, net::SocketAddr};
use std::sync::{Mutex, PoisonError};

use kcc_app::{
    mcp_settings::ListenerKind,
    permissions::KCC_ACCOUNT_ROLE,
    settings::{Config, McpConfig, mcp_schema::DedicatedTls},
};
use kcc_web::oauth::{Activation, OAuthServer, metadata::serve_jwks};
use rmcp_server_kit::oauth::OAuthConfig;
use serde_json::json;
use tokio::{net::TcpListener, runtime::Handle};

use crate::server_services::Services;

/// The scope kcc's tokens carry.
const SCOPE: &str = "mcp";

/// kcc's authorization server and its internal JWKS listener, shared by every
/// generation of the process.
#[derive(Debug)]
pub(crate) struct KccSignIn {
    /// The authorization server the Web UI serves.
    server: Arc<OAuthServer>,
    /// The internal JWKS listener's port, once started.
    jwks: Mutex<Option<u16>>,
}

impl KccSignIn {
    /// kcc sign-in through `server`; the JWKS listener starts on first use.
    pub(crate) const fn new(server: Arc<OAuthServer>) -> Self {
        Self {
            server,
            jwks: Mutex::new(None),
        }
    }

    /// The authorization server.
    pub(crate) const fn server(&self) -> &Arc<OAuthServer> {
        &self.server
    }

    /// The kit's OAuth configuration of the `kind` listener with `settings`, and what it
    /// accepts; starts the JWKS listener the first time. Blocking; inside the runtime.
    ///
    /// # Errors
    ///
    /// Why kcc sign-in cannot run: the signing key is unusable, no JWKS port could be
    /// bound, or the kit refused the configuration.
    pub(crate) fn listener(
        &self,
        config: &Config,
        settings: &McpConfig,
        kind: ListenerKind,
    ) -> Result<(OAuthConfig, Activation), String> {
        let port = self.jwks_port(iter::repeat(0))?;
        let (canonical, aliases) = resources(config, settings, kind);
        let issuer = self.server.issuer();
        let oauth: OAuthConfig = serde_json::from_value(json!({
            "issuer": issuer,
            "audience": canonical,
            "additional_audiences": aliases,
            "jwks_uri": format!("http://localhost:{port}/jwks"),
            "scopes": [{ "scope": SCOPE, "role": KCC_ACCOUNT_ROLE }],
            "allow_http_oauth_urls": true,
            "ssrf_allowlist": { "hosts": ["localhost"] },
            "allowed_algorithms": ["EdDSA"],
            "require_subject": true,
            "authorization_servers": [issuer],
            "audience_validation_mode": "strict",
        }))
        .map_err(|error| error.to_string())?;
        oauth.validate().map_err(|error| error.to_string())?;
        let accepted: BTreeSet<String> = iter::once(canonical).chain(aliases).collect();
        let lifetimes = (settings.auth.kcc.access_ttl, settings.auth.kcc.refresh_ttl);
        Ok((oauth, Activation::new(accepted, lifetimes)))
    }

    /// The JWKS listener's port: started on the first of `candidates` free on both
    /// loopback addresses, once for the process.
    ///
    /// # Errors
    ///
    /// The signing key is unusable or no port could be bound.
    pub(crate) fn jwks_port<I>(&self, candidates: I) -> Result<u16, String>
    where
        I: IntoIterator<Item = u16>,
    {
        let mut started = self.jwks.lock().unwrap_or_else(PoisonError::into_inner);
        if started.is_none() {
            *started = Some(self.start_jwks(candidates)?);
        }
        let port = *started;
        drop(started);
        port.ok_or_else(|| "the internal JWKS listener did not start".to_owned())
    }

    /// Starts the JWKS listener on the first of `candidates` free on both loopback
    /// addresses; its port.
    ///
    /// # Errors
    ///
    /// As [`KccSignIn::jwks_port`].
    fn start_jwks<I>(&self, candidates: I) -> Result<u16, String>
    where
        I: IntoIterator<Item = u16>,
    {
        let runtime = Handle::try_current().map_err(|error| error.to_string())?;
        let key = self
            .server
            .signing_key()
            .map_err(|error| error.to_string())?;
        let keys: Arc<[u8]> = serde_json::to_vec(&key.jwks())
            .map_err(|error| error.to_string())?
            .into();
        let bound = jwks::bind(candidates).map_err(|error| error.to_string())?;
        let port = bound.port();
        for std_listener in bound.into_listeners() {
            std_listener
                .set_nonblocking(true)
                .map_err(|error| error.to_string())?;
            let _guard = runtime.enter();
            let listener =
                TcpListener::from_std(std_listener).map_err(|error| error.to_string())?;
            drop(runtime.spawn(serving(listener, Arc::clone(&keys))));
        }
        tracing::info!(
            port,
            "internal JWKS listener started on the loopback addresses"
        );
        Ok(port)
    }
}

/// What the kcc sign-in listeners `activations` accept together: every resource, the
/// token lifetimes of the first; `None` when there is none.
pub(crate) fn united<'listener, I>(activations: I) -> Option<Activation>
where
    I: IntoIterator<Item = &'listener Activation>,
{
    let mut listeners = activations.into_iter();
    let first = listeners.next()?;
    let resources: BTreeSet<String> = first
        .resources
        .iter()
        .chain(listeners.flat_map(|activation| activation.resources.iter()))
        .cloned()
        .collect();
    Some(Activation::new(
        resources,
        (first.access_ttl, first.refresh_ttl),
    ))
}

/// kcc's authorization server for `config` over `services`' state and master key; `None`
/// without an issuer.
pub(crate) fn authorization_server(
    config: &Config,
    services: &Services,
) -> Option<Arc<OAuthServer>> {
    OAuthServer::of(
        config,
        (services.state.clone(), services.key.duplicate()),
        Arc::clone(&services.clock),
    )
    .map(Arc::new)
}

/// Serves the keys on `listener` until the process ends; an accept failure is logged.
// cancel-safe: only serves reads.
async fn serving(listener: TcpListener, keys: Arc<[u8]>) {
    if let Err(error) = serve_jwks(listener, keys).await {
        tracing::error!(%error, "the internal JWKS listener stopped");
    }
}

/// The `kind` listener's canonical MCP resource (what the kit's protected-resource
/// metadata advertises) and its aliases: the loopback names of its port and its public
/// URLs.
pub(crate) fn resources(
    config: &Config,
    settings: &McpConfig,
    kind: ListenerKind,
) -> (String, Vec<String>) {
    let dedicated = &settings.dedicated;
    let (tls, bind, port, (kit_public, other_public)) = if kind == ListenerKind::Main {
        (
            config.listener_tls(),
            format!(
                "{}:{}",
                config.server.listen_addr, config.server.listen_port
            ),
            config.server.listen_port,
            (
                config.server.public_url.clone(),
                config.web.public_url.as_ref().map(ToString::to_string),
            ),
        )
    } else {
        let tls = match dedicated.tls {
            DedicatedTls::Main => config.listener_tls(),
            DedicatedTls::SelfSigned => true,
            DedicatedTls::None | _ => false,
        };
        (
            tls,
            SocketAddr::new(dedicated.bind, dedicated.port).to_string(),
            dedicated.port,
            (dedicated.public_url.as_ref().map(ToString::to_string), None),
        )
    };
    let scheme = if tls { "https" } else { "http" };
    let resource = |url: &str| format!("{}/mcp", url.trim_end_matches('/'));
    let canonical = kit_public
        .as_deref()
        .map_or_else(|| format!("{scheme}://{bind}/mcp"), resource);
    let public: Vec<String> = other_public.as_deref().map(resource).into_iter().collect();
    let mut aliases: Vec<String> = ["127.0.0.1", "localhost", "[::1]"]
        .iter()
        .map(|host| format!("{scheme}://{host}:{port}/mcp"))
        .chain(public)
        .filter(|alias| *alias != canonical)
        .collect();
    aliases.sort();
    aliases.dedup();
    (canonical, aliases)
}
