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
pub mod errors;
pub mod nav;
pub mod page;
pub mod sse;
pub mod table;

mod assets;
mod pages;
mod prefs;

use core::time::Duration;

use axum::{
    Router,
    http::{HeaderValue, StatusCode, header},
    routing::get,
};
use kcc_i18n::locale::Locale;
use tower_http::{
    limit::RequestBodyLimitLayer, set_header::SetResponseHeaderLayer, timeout::TimeoutLayer,
};

use crate::sse::StreamLimiter;

/// Time limit for producing a response on every route except server-sent event streams.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Request body limit of every route except uploads, which set a larger one explicitly.
pub const BODY_LIMIT: usize = 1024 * 1024;

/// `Cache-Control` of every response that does not set its own: pages, redirects and
/// errors are never stored. Hash-addressed static assets set an immutable policy instead.
const NO_STORE: &str = "no-store, max-age=0";

/// Shared state of every Web UI handler.
#[derive(Debug, Clone)]
pub struct WebState {
    /// Locale used when neither the `kcc_lang` cookie nor `Accept-Language` selects one.
    default_locale: Locale,
    /// Open server-sent event streams per session.
    streams: StreamLimiter,
}

impl WebState {
    /// Creates the state with the configured default locale (`[web] default_locale`).
    #[inline]
    #[must_use]
    pub fn new(default_locale: Locale) -> Self {
        Self {
            default_locale,
            streams: StreamLimiter::default(),
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
    let bounded = Router::new()
        .route("/", get(pages::to_ui))
        .route("/ui", get(pages::to_ui))
        .route("/ui/", get(pages::dashboard))
        .route(assets::ROUTE, get(assets::serve))
        .route(
            "/ui/{*rest}",
            get(pages::section).fallback(pages::not_found),
        )
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
