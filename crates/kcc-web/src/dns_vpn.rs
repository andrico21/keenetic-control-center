//! The DNS and VPN pages of a router, built on the domain page kit.
//!
//! DNS (`/ui/r/{router}/dns`): the servers the router asks (over TLS, over HTTPS, plain),
//! content filtering (engine, interception, profiles and their assignments), static
//! records, domain lists and routes chosen by domain list.
//!
//! VPN (`/ui/r/{router}/vpn`): client connections by type with their state, a WireGuard
//! connection added from a form or imported from a `.conf` file, its peers, connections on
//! and off or deleted; the PPTP/L2TP, SSTP, OpenConnect and IPsec/IKEv2 servers and the
//! WireGuard server interfaces, and where users get their access.
//!
//! Each tab is one sortable, filterable table of 50 rows a page, or panels of settings;
//! its dialogs change it through the change workflow.
//!
//! Routes (route table: `Read`; every change re-checks its operation's permissions):
//!
//! - `GET /ui/r/{router}/dns` and `GET /ui/r/{router}/dns/{filtering|records|lists|routes}`:
//!   the DNS tabs; `GET|POST /ui/r/{router}/dns/form/{form}`: a dialog and its change;
//!   `POST /ui/r/{router}/dns/intercept`: interception on or off.
//! - `GET /ui/r/{router}/vpn`, `GET /ui/r/{router}/vpn/servers` and
//!   `GET /ui/r/{router}/vpn/peers/{tunnel}`: the VPN pages;
//!   `GET|POST /ui/r/{router}/vpn/form/{create|import|peer|pool|dns|ipsec}`: a dialog and
//!   its change; `POST /ui/r/{router}/vpn/{state|service}`: a connection or a server on or
//!   off; `GET|POST /ui/r/{router}/vpn/delete`: a connection deleted, its name typed.
//! - `POST /ui/r/{router}/vpn/import`: the `.conf` upload, from [`uploads`].

mod cells;
mod check;
mod dns_checks;
mod dns_filtering;
mod dns_forms;
mod dns_pages;
mod dns_read;
mod dns_tabs;
mod flow;
mod form;
mod listing;
mod region;
mod screen;
mod vpn_actions;
mod vpn_checks;
mod vpn_conf;
mod vpn_forms;
mod vpn_import;
mod vpn_pages;
mod vpn_read;
mod vpn_servers_tab;
mod vpn_tabs;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::StatusCode,
    middleware,
    routing::{get, post},
};
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer};

use crate::{REQUEST_TIMEOUT, WebState, protect};

/// The DNS and VPN page and action routes.
pub(crate) fn routes() -> Router<WebState> {
    Router::new()
        .route("/ui/r/{router}/dns", get(dns_pages::servers))
        .route("/ui/r/{router}/dns/intercept", post(dns_pages::intercept))
        .route(
            "/ui/r/{router}/dns/form/{form}",
            get(dns_pages::dialog).post(dns_pages::submit),
        )
        .route("/ui/r/{router}/dns/{tab}", get(dns_pages::tab))
        .route("/ui/r/{router}/vpn", get(vpn_pages::connections))
        .route("/ui/r/{router}/vpn/servers", get(vpn_pages::servers))
        .route("/ui/r/{router}/vpn/peers/{tunnel}", get(vpn_pages::peers))
        .route(
            "/ui/r/{router}/vpn/form/{form}",
            get(vpn_pages::dialog).post(vpn_pages::submit),
        )
        .route("/ui/r/{router}/vpn/state", post(vpn_actions::switch))
        .route("/ui/r/{router}/vpn/service", post(vpn_actions::service))
        .route(
            "/ui/r/{router}/vpn/delete",
            get(vpn_actions::delete_dialog).post(vpn_actions::delete),
        )
}

/// The WireGuard `.conf` upload, with its own 64 KiB body limit.
///
/// `web_router` merges it after the global body limit. The `RequestBodyLimitLayer` is the
/// limit, refusing a declared length over it and cutting a longer stream; axum's
/// `DefaultBodyLimit` is disabled on the route so that a second limit does not hide the
/// first one's error from the multipart reader. A body over the limit is answered with
/// the import dialog and its localized size error, as 413.
pub(crate) fn uploads(state: &WebState) -> Router<WebState> {
    let route = Router::new()
        .route("/ui/r/{router}/vpn/import", post(vpn_import::import))
        .route_layer(DefaultBodyLimit::disable())
        .route_layer(RequestBodyLimitLayer::new(vpn_import::UPLOAD_LIMIT))
        .route_layer(middleware::from_fn(vpn_import::limit));
    protect(route, state).route_layer(TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        REQUEST_TIMEOUT,
    ))
}
