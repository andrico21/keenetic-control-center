//! The wizard's routes and their layers, merged once by `web_router`.
//!
//! The routes join the Web UI after its global body limit, so they carry their own:
//! 1 MiB, the step-1 upload included (axum's own limit is off there, so the one limit's
//! error reaches the multipart reader, and a bare 413 becomes the localized size error).
//! Pages and actions run under the request timeout, the event stream outside it (capped
//! per session by the stream limiter); every route passes the CSRF, authentication and
//! route-table authorization layers (`Migrate`).

use alloc::sync::Arc;

use axum::{
    Extension, Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
};
use tower_http::limit::RequestBodyLimitLayer;

use super::{
    apply, downloads, inputs_submit, landing, mapping_submit, record::Record, review_submit,
    source, source_read, target, target_confirm,
};
use crate::{
    BODY_LIMIT, WebState, brackets, protect,
    wizard::{events, finish, resume, running, service::Wizards, settle},
};

/// Every wizard route.
pub(crate) fn router(state: &WebState) -> Router<WebState> {
    let wizards = Arc::new(Wizards::<Record>::default());
    let pages = Router::new()
        .route("/ui/migrate", get(landing::page).post(landing::start))
        .route("/ui/migrate/{id}", get(resume::page::<Record>))
        .route("/ui/migrate/{id}/back", post(resume::back::<Record>))
        .route("/ui/migrate/{id}/target", post(target::choose))
        .route(
            "/ui/migrate/{id}/target/continue",
            post(target_confirm::confirm),
        )
        .route("/ui/migrate/{id}/mapping", post(mapping_submit::submit))
        .route("/ui/migrate/{id}/review", post(review_submit::save))
        .route(
            "/ui/migrate/{id}/review/continue",
            post(review_submit::proceed),
        )
        .route("/ui/migrate/{id}/inputs", post(inputs_submit::submit))
        .route("/ui/migrate/{id}/download/{file}", get(downloads::download))
        .route("/ui/migrate/{id}/apply", post(apply::apply))
        .route("/ui/migrate/{id}/stop", post(running::stop::<Record>))
        .route("/ui/migrate/{id}/results", post(resume::results::<Record>))
        .route("/ui/migrate/{id}/commit", post(finish::commit::<Record>))
        .route(
            "/ui/migrate/{id}/rollback",
            post(finish::rollback::<Record>),
        )
        .route("/ui/migrate/{id}/{way}", post(settle::way::<Record>))
        .route_layer(RequestBodyLimitLayer::new(BODY_LIMIT));
    let upload = Router::new()
        .route("/ui/migrate/{id}/source", post(source::submit))
        .route_layer(DefaultBodyLimit::disable())
        .route_layer(RequestBodyLimitLayer::new(BODY_LIMIT))
        .route_layer(middleware::from_fn(source_read::limit));
    let bounded =
        protect(pages.merge(upload), state).route_layer(middleware::from_fn(brackets::budget));
    let streams = protect(
        Router::new().route("/ui/migrate/{id}/events", get(events::events::<Record>)),
        state,
    );
    bounded.merge(streams).route_layer(Extension(wizards))
}
