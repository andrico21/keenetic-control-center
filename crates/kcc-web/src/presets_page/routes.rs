//! The presets' routes and their layers, merged once by `web_router`.
//!
//! As the migration wizard's: the routes join the Web UI after its global body limit, so
//! they carry their own, 1 MiB, the new preset's upload included (axum's own limit is off
//! there, so a bare 413 becomes the localized size error beside the file input). Pages
//! and actions run under the request timeout, the event stream outside it; every route
//! passes the CSRF, authentication and route-table authorization layers.

use alloc::sync::Arc;

use axum::{
    Extension, Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
};
use tower_http::limit::RequestBodyLimitLayer;

use super::{
    apply, capture, compose, delete, detail, downloads, drafts::Drafts, inputs, landing, list,
    options, record::Record, reveal, review_submit, source, target_submit,
};
use crate::{
    BODY_LIMIT, WebState, brackets,
    migrate_wizard::source_read,
    protect,
    wizard::{events, finish, resume, running, service::Wizards},
};

/// Every preset route.
pub(crate) fn router(state: &WebState) -> Router<WebState> {
    let runs = Arc::new(Wizards::<Record>::default());
    let drafts = Arc::new(Drafts::default());
    let pages = Router::new()
        .route("/ui/presets", get(list::page))
        .route(
            "/ui/presets/new/{draft}",
            get(compose::page).post(compose::save),
        )
        .route("/ui/presets/new/{draft}/preview", post(compose::preview))
        .route("/ui/presets/{id}", get(detail::page))
        .route("/ui/presets/{id}/reveal", post(reveal::preset))
        .route(
            "/ui/presets/{id}/delete",
            get(delete::dialog).post(delete::delete),
        )
        .route(
            "/ui/presets/{id}/apply",
            get(landing::preset_page).post(landing::preset_start),
        )
        .route(
            "/ui/copy",
            get(landing::copy_page).post(landing::copy_start),
        )
        .route("/ui/presets/runs/{run}", get(resume::page::<Record>))
        .route("/ui/presets/runs/{run}/back", post(resume::back::<Record>))
        .route("/ui/presets/runs/{run}/source", post(source::submit))
        .route("/ui/presets/runs/{run}/target", post(target_submit::choose))
        .route(
            "/ui/presets/runs/{run}/target/continue",
            post(target_submit::confirm),
        )
        .route("/ui/presets/runs/{run}/options", post(options::submit))
        .route("/ui/presets/runs/{run}/review", post(review_submit::save))
        .route(
            "/ui/presets/runs/{run}/review/continue",
            post(review_submit::proceed),
        )
        .route("/ui/presets/runs/{run}/inputs", post(inputs::submit))
        .route("/ui/presets/runs/{run}/reveal", post(reveal::commands))
        .route("/ui/presets/runs/{run}/apply", post(apply::apply))
        .route("/ui/presets/runs/{run}/stop", post(running::stop::<Record>))
        .route(
            "/ui/presets/runs/{run}/results",
            post(resume::results::<Record>),
        )
        .route(
            "/ui/presets/runs/{run}/download/{file}",
            get(downloads::download),
        )
        .route(
            "/ui/presets/runs/{run}/{way}",
            post(finish::choose::<Record>),
        )
        .route_layer(RequestBodyLimitLayer::new(BODY_LIMIT));
    let upload = Router::new()
        .route("/ui/presets/new", get(capture::page).post(capture::read))
        .route_layer(DefaultBodyLimit::disable())
        .route_layer(RequestBodyLimitLayer::new(BODY_LIMIT))
        .route_layer(middleware::from_fn(source_read::limit));
    let bounded =
        protect(pages.merge(upload), state).route_layer(middleware::from_fn(brackets::budget));
    let streams = protect(
        Router::new().route(
            "/ui/presets/runs/{run}/events",
            get(events::events::<Record>),
        ),
        state,
    );
    bounded
        .merge(streams)
        .route_layer(Extension(runs))
        .route_layer(Extension(drafts))
}
