//! A connection's routing on the internet page: its place in the priority order and PPP's
//! default route.
//!
//! Move up and Move down swap a connection's priority with its neighbour's, in one change
//! of two lines; the default-route button turns PPP's default route on or off.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::{DomainError, wan};
use kcc_rci::ObjectName;

use crate::{
    WebState,
    authz::CurrentUser,
    net_change::{merged, refreshed},
    net_pages::{Call, Tab},
    net_wan::{Link, links},
    page_kit::{
        action::Operation,
        change::Change,
        request::{Params, missing},
        respond::Answer,
        submit::{Formless, Invalid, Planned, Submission},
    },
};

/// The priority order, audited as `web.wan_priority`.
const PRIORITY: Operation = Operation::write(&wan::DESCRIPTOR, "priority", "web.wan_priority");

/// PPP's default route, audited as `web.wan_default_route`.
const DEFAULT_ROUTE: Operation =
    Operation::write(&wan::DESCRIPTOR, "default_route", "web.wan_default_route");

/// `POST /ui/r/{router}/internet/default-route?name=&use=yes|no`: turns PPP's default
/// route on or off.
///
/// # Errors
///
/// Answers 404 for a missing connection name or choice, and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn default_route(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let params = Params::new(query, form);
    let name = params.object("name")?;
    let enabled = match params.get("use") {
        Some("yes") => true,
        Some("no") => false,
        Some(_) | None => return Err(missing()),
    };
    let action = DEFAULT_ROUTE.open(&state, &user, &router).await?;
    let call = Call::new(&state, &user, &router, &headers).on(Tab::Internet);
    Ok(Submission::new(action, &params, Formless)
        .submit(
            |_params| Ok(()),
            async |(), domain| {
                let operation = wan::plan_default_route(domain, &name, enabled)?;
                let request = wan::change_request(&name, &operation)?;
                Ok(Planned::of(&[operation], Change::Cli(request)))
            },
            async |domain| refreshed(call, domain).await,
        )
        .await)
}

/// `POST /ui/r/{router}/internet/order?name=&move=up|down`: swaps the connection's
/// priority with its neighbour's in priority order.
///
/// # Errors
///
/// Answers 404 for a missing connection name or direction, or when the connection has no
/// neighbour to swap with, and what the kit answers when the router or the permission is
/// missing.
pub(crate) async fn order(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let params = Params::new(query, form);
    let name = params.object("name")?;
    let up = match params.get("move") {
        Some("up") => true,
        Some("down") => false,
        Some(_) | None => return Err(missing()),
    };
    let action = PRIORITY.open(&state, &user, &router).await?;
    let found = links(&action.context().await?).await;
    let call = Call::new(&state, &user, &router, &headers).on(Tab::Internet);
    Ok(Submission::new(action, &params, Formless)
        .submit(
            |_params| match found {
                Ok(listed) => {
                    let moves = reorder(&listed, name.as_str(), up);
                    if moves.is_empty() {
                        Err(Invalid::from(Vec::new()))
                    } else {
                        Ok(Ok(moves))
                    }
                }
                Err(error) => Ok(Err(error)),
            },
            async |moves, domain| {
                let mut operations = Vec::new();
                let mut requests = Vec::new();
                for (id, priority) in moves? {
                    let object =
                        ObjectName::try_from(id).map_err(|_error| DomainError::InvalidResponse)?;
                    let operation = wan::plan_priority(domain, &object, priority).await?;
                    requests.push(wan::change_request(&object, &operation)?);
                    operations.push(operation);
                }
                Ok(Planned::of(&operations, Change::Cli(merged(requests)?)))
            },
            async |domain| refreshed(call, domain).await,
        )
        .await)
}

/// The priority changes that move `name` one place up (or down) among `links`.
///
/// `links` are in priority order, highest first. The connection swaps priorities with its
/// neighbour, or goes one past it when both are equal. Empty when it has no neighbour
/// there or a priority is not reported.
pub(crate) fn reorder(links: &[Link], name: &str, up: bool) -> Vec<(String, i64)> {
    let Some(index) = links.iter().position(|link| link.id() == name) else {
        return Vec::new();
    };
    let neighbour = if up {
        index.checked_sub(1)
    } else {
        index.checked_add(1)
    };
    let Some(other) = neighbour.and_then(|at| links.get(at)) else {
        return Vec::new();
    };
    let (Some(mine), Some(theirs)) = (links.get(index).and_then(Link::priority), other.priority())
    else {
        return Vec::new();
    };
    if mine != theirs {
        return vec![(name.to_owned(), theirs), (other.id().to_owned(), mine)];
    }
    let moved = if up {
        theirs.saturating_add(1)
    } else {
        theirs.saturating_sub(1)
    };
    vec![(name.to_owned(), moved)]
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use kcc_domain::wan::Connection;
    use serde_json::json;

    use super::reorder;
    use crate::net_wan::Link;

    /// A PPPoE connection `id` with `priority`, as the router reports it.
    fn link(id: &str, priority: Option<i64>) -> Result<Link, Box<dyn Error>> {
        let connection: Connection =
            serde_json::from_value(json!({"id": id, "type": "PPPoE", "priority": priority}))?;
        Ok(Link::new(id.to_owned(), &connection))
    }

    #[test]
    fn neighbours_swap_priorities_and_equal_ones_move_past() -> Result<(), Box<dyn Error>> {
        let ordered = [
            link("PPPoE0", Some(900))?,
            link("PPPoE1", Some(800))?,
            link("PPPoE2", Some(700))?,
        ];
        assert_eq!(
            reorder(&ordered, "PPPoE2", true),
            [("PPPoE2".to_owned(), 800), ("PPPoE1".to_owned(), 700)],
            "up swaps with the one above"
        );
        assert_eq!(
            reorder(&ordered, "PPPoE0", false),
            [("PPPoE0".to_owned(), 800), ("PPPoE1".to_owned(), 900)],
            "down swaps with the one below"
        );
        assert!(
            reorder(&ordered, "PPPoE0", true).is_empty(),
            "the first stays"
        );
        assert!(
            reorder(&ordered, "PPPoE2", false).is_empty(),
            "the last stays"
        );
        assert!(reorder(&ordered, "L2TP0", true).is_empty(), "unknown name");
        let equal = [link("PPPoE0", Some(500))?, link("PPPoE1", Some(500))?];
        assert_eq!(
            reorder(&equal, "PPPoE1", true),
            [("PPPoE1".to_owned(), 501)],
            "an equal neighbour is passed"
        );
        let unreported = [link("PPPoE0", None)?, link("PPPoE1", Some(800))?];
        assert!(
            reorder(&unreported, "PPPoE1", true).is_empty(),
            "no swap without both priorities"
        );
        Ok(())
    }
}
