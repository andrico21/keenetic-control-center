//! The routing page routes, merged once in `web_router`.

use axum::{
    Router,
    routing::{get, post},
};

use super::{policy_actions, policy_forms, policy_view, route_add, route_remove, route_views};
use crate::WebState;

/// The static routes, routing table and connection policy routes.
pub(crate) fn routes() -> Router<WebState> {
    Router::new()
        .route("/ui/r/{router}/routing", get(route_views::routes_v4))
        .route("/ui/r/{router}/routing/ipv6", get(route_views::routes_v6))
        .route("/ui/r/{router}/routing/table", get(route_views::table_v4))
        .route(
            "/ui/r/{router}/routing/table/ipv6",
            get(route_views::table_v6),
        )
        .route(
            "/ui/r/{router}/routing/route/new",
            get(route_add::dialog).post(route_add::add),
        )
        .route(
            "/ui/r/{router}/routing/route/remove",
            get(route_remove::dialog).post(route_remove::remove),
        )
        .route("/ui/r/{router}/routing/policies", get(policy_view::page))
        .route(
            "/ui/r/{router}/routing/policy/new",
            get(policy_forms::create_dialog).post(policy_forms::create),
        )
        .route(
            "/ui/r/{router}/routing/policy/description",
            get(policy_forms::description_dialog).post(policy_forms::describe),
        )
        .route(
            "/ui/r/{router}/routing/policy/permit",
            get(policy_forms::permit_dialog).post(policy_forms::permit),
        )
        .route(
            "/ui/r/{router}/routing/policy/unpermit",
            post(policy_actions::unpermit),
        )
        .route(
            "/ui/r/{router}/routing/policy/multipath",
            post(policy_actions::multipath),
        )
        .route(
            "/ui/r/{router}/routing/policy/delete",
            get(policy_actions::delete_dialog).post(policy_actions::delete),
        )
}
