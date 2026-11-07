//! The port forwarding page routes, merged once in `web_router`.

use axum::{Router, routing::get};

use super::{actions, forward_forms, interfaces, sessions, views};
use crate::WebState;

/// The rules, translated interfaces and active connections routes.
pub(crate) fn routes() -> Router<WebState> {
    Router::new()
        .route("/ui/r/{router}/nat", get(views::rules))
        .route("/ui/r/{router}/nat/interfaces", get(interfaces::interfaces))
        .route("/ui/r/{router}/nat/sessions", get(sessions::sessions))
        .route(
            "/ui/r/{router}/nat/forward/new",
            get(forward_forms::dialog).post(forward_forms::add),
        )
        .route(
            "/ui/r/{router}/nat/forward/remove",
            get(actions::remove_dialog).post(actions::remove),
        )
        .route(
            "/ui/r/{router}/nat/interface/new",
            get(actions::translate_dialog).post(actions::translate),
        )
        .route(
            "/ui/r/{router}/nat/interface/remove",
            get(actions::untranslate_dialog).post(actions::untranslate),
        )
}
