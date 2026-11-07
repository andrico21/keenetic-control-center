//! The configuration page's routes and their layers.
//!
//! `web_router` merges them in one line after its global body limit, as it does with the
//! other upload routes: the pages and actions get the same protection (CSRF,
//! authentication, route-table authorization), the request timeout and the global body
//! limit here, and the upload its own larger limit, mapped to the dialog's localized size
//! error.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::StatusCode,
    middleware,
    routing::{get, post},
};
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer};

use super::{compare, create, download, landing, page, restore, safety, upload};
use crate::{BODY_LIMIT, REQUEST_TIMEOUT, WebState, protect};

/// Every route of the configuration page.
pub(crate) fn routes(state: &WebState) -> Router<WebState> {
    let pages = Router::new()
        .route("/ui/configuration", get(landing::page))
        .route("/ui/r/{router}/config", get(page::page))
        .route("/ui/r/{router}/config/diff", get(compare::page))
        .route("/ui/r/{router}/config/save", post(safety::save))
        .route("/ui/r/{router}/config/commit", post(safety::commit))
        .route("/ui/r/{router}/config/rollback", post(safety::rollback))
        .route("/ui/r/{router}/config/upload", get(upload::dialog))
        .route("/ui/r/{router}/config/backups", post(create::create))
        .route(
            "/ui/r/{router}/config/backups/download",
            get(download::download),
        )
        .route("/ui/r/{router}/config/backups/delete", post(create::delete))
        .route(
            "/ui/r/{router}/config/backups/raw-restore",
            post(restore::raw_restore),
        )
        .route_layer(RequestBodyLimitLayer::new(BODY_LIMIT));
    let uploads = Router::new()
        .route("/ui/r/{router}/config/backups/upload", post(upload::upload))
        .route_layer(DefaultBodyLimit::disable())
        .route_layer(RequestBodyLimitLayer::new(upload::BODY_LIMIT))
        .route_layer(middleware::from_fn(upload::limit));
    protect(pages.merge(uploads), state).route_layer(TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        REQUEST_TIMEOUT,
    ))
}
