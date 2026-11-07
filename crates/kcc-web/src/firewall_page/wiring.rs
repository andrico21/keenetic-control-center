//! The firewall page routes, merged once in `web_router`.

use axum::{
    Router,
    routing::{get, post},
};

use super::{bind, rule_actions, rule_forms, rule_props, views};
use crate::WebState;

/// The access list, binding and UPnP routes.
pub(crate) fn routes() -> Router<WebState> {
    Router::new()
        .route("/ui/r/{router}/firewall", get(views::lists))
        .route("/ui/r/{router}/firewall/interfaces", get(views::bindings))
        .route("/ui/r/{router}/firewall/upnp", get(views::upnp))
        .route(
            "/ui/r/{router}/firewall/rule/new",
            get(rule_forms::add_dialog).post(rule_forms::add),
        )
        .route(
            "/ui/r/{router}/firewall/rule/description",
            get(rule_props::description_dialog).post(rule_props::describe),
        )
        .route(
            "/ui/r/{router}/firewall/rule/schedule",
            get(rule_props::schedule_dialog).post(rule_props::schedule),
        )
        .route(
            "/ui/r/{router}/firewall/rule/remove",
            get(rule_actions::remove_dialog).post(rule_actions::remove),
        )
        .route(
            "/ui/r/{router}/firewall/rule/move",
            post(rule_actions::move_rule),
        )
        .route(
            "/ui/r/{router}/firewall/rule/state",
            post(rule_actions::switch),
        )
        .route(
            "/ui/r/{router}/firewall/bind",
            get(bind::bind_dialog).post(bind::bind),
        )
        .route(
            "/ui/r/{router}/firewall/unbind",
            get(bind::unbind_dialog).post(bind::unbind),
        )
}
