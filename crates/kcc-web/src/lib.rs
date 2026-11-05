//! Web UI: server-rendered pages under `/ui`, merged into the rmcp-server-kit router.
//!
//! [`web_router`] builds the router `kcc` passes to `McpServerConfig::with_extra_router`.
//! The kit owns `/mcp`, `/healthz`, `/readyz`, `/version`, `/admin/status` and
//! `/.well-known/*` and panics on an exact overlap, so every Web UI route lives under
//! `/ui`; the one other route is `GET /`, a redirect to `/ui/`.
//!
//! - Pages are askama templates from `templates/` with HTML auto-escaping; every
//!   user-visible string comes from `kcc-i18n` through the templates' `t(...)` calls.
//! - Static assets are embedded, addressed by content hash under `/ui/static/` and served
//!   with an immutable cache policy; vendored files are pinned in `assets/ASSETS.lock`.
//! - [`csp::security_headers`] is the kit's security-header configuration: the Web UI
//!   Content-Security-Policy, and no kit `Cache-Control`, because the kit would overwrite
//!   the per-response value this router sets.
//! - Unknown paths under `/ui` render a generic, localized 404 page ([`errors`]).
// `dead_code_pub_in_binary` fires on the public API only in the lib unit-test
// binary; rustc accepts an expect for it at crate level alone.
#![cfg_attr(
    test,
    expect(
        dead_code_pub_in_binary,
        reason = "public API: unused inside the unit-test harness"
    )
)]

extern crate alloc;

pub mod csp;
mod csrf;
pub mod errors;
pub mod nav;
pub mod page;
pub mod session;
pub mod sse;
pub mod table;

mod auth;
mod authz;

mod assets;
mod pages;
mod prefs;

use alloc::sync::Arc;
use core::{fmt, time::Duration};

use axum::{
    Router,
    http::{HeaderValue, StatusCode, header},
    middleware,
    routing::{get, post},
};
use kcc_app::{
    accounts::{AccountStore, Clock},
    audit::AuditLog,
    permissions::Role,
};
use kcc_i18n::locale::Locale;
use tower_http::{
    limit::RequestBodyLimitLayer, set_header::SetResponseHeaderLayer, timeout::TimeoutLayer,
};

use crate::{
    session::{CookieSecurity, SessionStore},
    sse::StreamLimiter,
};

/// Time limit for producing a response on every route except server-sent event streams.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Request body limit of every route except uploads, which set a larger one explicitly.
pub const BODY_LIMIT: usize = 1024 * 1024;

/// `Cache-Control` of every response that does not set its own: pages, redirects and
/// errors are never stored. Hash-addressed static assets set an immutable policy instead.
const NO_STORE: &str = "no-store, max-age=0";

/// Shared state of every Web UI handler.
#[derive(Clone)]
pub struct WebState {
    /// Locale used when neither the `kcc_lang` cookie nor `Accept-Language` selects one.
    default_locale: Locale,
    /// Open server-sent event streams per session.
    streams: StreamLimiter,
    /// Persistent account service.
    accounts: Arc<AccountStore>,
    /// In-memory browser sessions.
    sessions: SessionStore,
    /// Tamper-evident audit writer.
    audit: AuditLog,
    /// Built-in and custom roles resolved at startup.
    roles: Arc<[Role]>,
    /// Origins accepted for browser state-changing requests.
    allowed_origins: Arc<[String]>,
    /// Cookie policy selected from the actual listener transport.
    cookie_security: CookieSecurity,
    /// Wall clock shared with account lockout and audit timestamps.
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for WebState {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebState").finish_non_exhaustive()
    }
}

/// Security services and listener facts needed to build [`WebState`].
#[derive(Debug)]
#[expect(
    clippy::exhaustive_structs,
    reason = "application integration constructs the complete validated Web state"
)]
pub struct WebStateConfig {
    /// Locale used before login or when an account locale is invalid.
    pub default_locale: Locale,
    /// Persistent account service.
    pub accounts: Arc<AccountStore>,
    /// Tamper-evident audit writer.
    pub audit: AuditLog,
    /// Roles loaded from application state.
    pub roles: Vec<Role>,
    /// Session idle timeout.
    pub session_idle: Duration,
    /// Session absolute timeout.
    pub session_absolute: Duration,
    /// Origin allowlist derived by `Config::web_allowed_origins`.
    pub allowed_origins: Vec<String>,
    /// Cookie transport selected from the actual listener.
    pub cookie_security: CookieSecurity,
    /// Shared wall clock.
    pub clock: Arc<dyn Clock>,
}

impl WebState {
    /// Creates the state from validated application services and listener facts.
    #[inline]
    #[must_use]
    pub fn new(config: WebStateConfig) -> Self {
        let sessions = SessionStore::new(
            config.session_idle,
            config.session_absolute,
            config.default_locale,
            Arc::clone(&config.clock),
        );
        Self {
            default_locale: config.default_locale,
            streams: StreamLimiter::default(),
            accounts: config.accounts,
            sessions,
            audit: config.audit,
            roles: config.roles.into(),
            allowed_origins: config.allowed_origins.into(),
            cookie_security: config.cookie_security,
            clock: config.clock,
        }
    }

    /// The locale used when a request does not select one.
    #[inline]
    #[must_use]
    pub const fn default_locale(&self) -> Locale {
        self.default_locale
    }

    /// The per-session limit on concurrent server-sent event streams.
    #[inline]
    #[must_use]
    pub const fn streams(&self) -> &StreamLimiter {
        &self.streams
    }

    /// Account service used by login and account settings.
    #[inline]
    #[must_use]
    pub(crate) const fn accounts(&self) -> &Arc<AccountStore> {
        &self.accounts
    }

    /// In-memory session store.
    #[inline]
    #[must_use]
    pub(crate) const fn sessions(&self) -> &SessionStore {
        &self.sessions
    }

    /// Audit writer for authentication events.
    #[inline]
    #[must_use]
    pub(crate) const fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// Resolves an account's persisted role name.
    #[must_use]
    pub(crate) fn role(&self, name: &str) -> Option<Role> {
        self.roles.iter().find(|role| role.name == name).cloned()
    }

    /// Origins accepted for state-changing browser requests.
    #[inline]
    #[must_use]
    pub(crate) fn allowed_origins(&self) -> &[String] {
        &self.allowed_origins
    }

    /// Session cookie policy for this listener.
    #[inline]
    #[must_use]
    pub(crate) const fn cookie_security(&self) -> CookieSecurity {
        self.cookie_security
    }

    /// Current Unix timestamp for audit records.
    #[inline]
    #[must_use]
    pub(crate) fn unix_seconds(&self) -> u64 {
        self.clock.unix_seconds()
    }
}

/// Builds the Web UI router for `McpServerConfig::with_extra_router`.
///
/// Layering contract for the routes later pages add:
///
/// - Request/response routes join `bounded`, under the [`REQUEST_TIMEOUT`].
/// - Server-sent event routes are merged after the timeout layer and before the body
///   limit, so the timeout never cuts a stream; [`WebState::streams`] caps them per
///   session.
/// - Upload routes are merged after the [`BODY_LIMIT`] layer, each with its own larger
///   `RequestBodyLimitLayer` and axum `DefaultBodyLimit`.
/// - The kit installs its JSON 404 after merging this router, so `/ui/{*rest}` is an
///   explicit route that renders the HTML 404 page for every unknown path.
#[inline]
pub fn web_router(state: WebState) -> Router {
    let protected = Router::new()
        .route("/", get(pages::to_ui))
        .route("/ui", get(pages::to_ui))
        .route("/ui/", get(pages::dashboard))
        .route("/ui/account", get(auth::account_page))
        .route("/ui/account/password", post(auth::change_password))
        .route("/ui/account/locale", post(auth::change_locale))
        .route("/ui/logout", post(auth::logout))
        .route(
            "/ui/{*rest}",
            get(pages::section).fallback(pages::not_found),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            authz::authorization_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            authz::authentication_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            csrf::middleware,
        ));
    let public = Router::new()
        .route(assets::ROUTE, get(assets::serve))
        .route("/ui/login", get(auth::login_page).post(auth::login))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            csrf::middleware,
        ));
    let bounded =
        Router::new()
            .merge(public)
            .merge(protected)
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                REQUEST_TIMEOUT,
            ));
    Router::new()
        .merge(bounded)
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static(NO_STORE),
        ))
        .with_state(state)
}
