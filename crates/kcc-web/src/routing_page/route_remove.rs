//! Remove route: a plain confirmation, then the removal through the route-wipe guard.
//!
//! When the router answers a single removal by clearing every static route, the routing
//! domain puts back each route the router had just before and stops; the page reads the
//! routes back and says so prominently, naming what came back or what did not.

use core::slice;

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_app::workflow::WorkflowError;
use kcc_domain::{ChangeOp, DomainError, routing::change};
use kcc_i18n::{bundle::tr, keys};
use serde::Deserialize;

use super::{
    guard::Guard,
    reply::{ConfirmDialog, answer, gone, guarded, refused, unread},
    route_add::{operation, read_static},
    route_rows::{Family, StaticRoute, static_routes},
    route_views::{read_table, static_region},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        audit::Record,
        change::Applied,
        failure::plan_failure,
        family::Family as Words,
        outcome::{Failure, Outcome},
        request::{missing, rendered, shown_query, with_query},
        respond::Answer,
        submit::{
            Planned,
            work::{Report, Stopped},
        },
    },
};

/// The route a removal names, as the static routes table links it.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct RouteQuery {
    /// `ipv4` or `ipv6`.
    #[serde(default)]
    family: Option<String>,
    /// Network or prefix.
    #[serde(default)]
    destination: String,
    /// IPv4 mask.
    #[serde(default)]
    mask: Option<String>,
    /// Next hop.
    #[serde(default)]
    gateway: Option<String>,
    /// Egress interface.
    #[serde(default)]
    interface: Option<String>,
    /// Route metric.
    #[serde(default)]
    metric: Option<String>,
}

impl RouteQuery {
    /// The route named, or 404 for a malformed one.
    ///
    /// # Errors
    ///
    /// Answers 404 when a value is not in its family's form.
    fn route(&self) -> Result<StaticRoute, Answer> {
        let family = Family::from_slug(self.family.as_deref()).ok_or_else(missing)?;
        let metric = match self.metric.as_deref() {
            Some(text) => Some(text.parse::<u32>().map_err(|_error| missing())?),
            None => None,
        };
        let route = StaticRoute::new(
            family,
            (self.destination.clone(), self.mask.clone()),
            (self.gateway.clone(), self.interface.clone()),
            metric,
        );
        if route.well_formed() {
            Ok(route)
        } else {
            Err(missing())
        }
    }
}

/// The address of the removal of `route` on `router`.
fn action_url(router: &str, route: &StaticRoute) -> String {
    let pairs = route.pairs();
    let borrowed: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    with_query(&format!("/ui/r/{router}/routing/route/remove"), &borrowed)
}

/// `GET /ui/r/{router}/routing/route/remove?family=&destination=&...`: asks first.
///
/// # Errors
///
/// Answers 404 for a malformed route, and what the kit answers when the router or the
/// permission is missing.
// NOT cancel-safe: a refused or failed open queues an audit entry that may be written after the
// future is dropped; otherwise it only reads.
pub(crate) async fn dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<RouteQuery>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let route = query.route()?;
    let action = operation(route.family(), "web.routing_route_remove")
        .open(&state, &user, &router)
        .await?;
    let locale = action.locale();
    let mut args = FluentArgs::new();
    args.set("network", route.destination());
    let title = tr(locale, keys::WEB_ROUTING_REMOVE_TITLE, Some(&args));
    let url = action_url(&router, &route);
    Ok(ConfirmDialog::new(locale, title, keys::WEB_ROUTING_REMOVE_TEXT, url).show())
}

/// `operation`, the removal of `route` through the route-wipe guard; a removal the guard
/// stopped reports how it ended beyond the kit's outcome.
fn removal(operation: &ChangeOp, route: StaticRoute) -> Planned {
    let family = route.family();
    Planned::reporting(slice::from_ref(operation), move |changes, context| {
        Box::pin(async move {
            let removed = match family {
                Family::V4 => change::remove_ipv4(changes, context, &route.ipv4()).await,
                Family::V6 => change::remove_ipv6(changes, context, &route.ipv6()).await,
            };
            let report = match removed {
                Ok(result) => {
                    return Ok(Applied::Cli {
                        unsaved: result.unsaved,
                        responses: result.responses,
                    });
                }
                Err(DomainError::SafetyAbort) => {
                    let last = changes.current_last_change().await;
                    Report::RoutesWiped {
                        unsaved: last.map_or(true, |found| found.unsaved),
                    }
                }
                Err(DomainError::RouteCountMismatch) => Report::RouteCountMismatch,
                Err(other) => return Err(Stopped::from(WorkflowError::from(other))),
            };
            let failed = WorkflowError::VerificationFailed {
                field: family.command().to_owned(),
            };
            Err(Stopped::reporting(failed, Some(report)))
        })
    })
}

/// `POST /ui/r/{router}/routing/route/remove?...`: removes the route through the
/// route-wipe guard and answers with its outcome, the guard's banner when it acted, and
/// the routes read back.
///
/// # Errors
///
/// Answers 404 for a malformed route, and what the kit answers when the router or the
/// permission is missing.
// NOT cancel-safe: dropped after `run_planned` sends the removal, the router may keep it without
// its read-back, the route-wipe check or its audit entry.
pub(crate) async fn remove(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<RouteQuery>,
    headers: HeaderMap,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let route = query.route()?;
    let family = route.family();
    let action = operation(family, "web.routing_route_remove")
        .open(&state, &user, &router)
        .await?;
    let locale = action.locale();
    let domain = action.context().await?;
    let before = match read_table(&domain, family).await {
        Ok(entries) => static_routes(family, &entries),
        Err(message) => return Ok(refused(action, unread(locale, message)).await),
    };
    if !before.contains(&route) {
        return Ok(refused(action, gone(locale)).await);
    }
    let planned = match family {
        Family::V4 => change::plan_remove_ipv4(&domain, &route.ipv4()),
        Family::V6 => change::plan_remove_ipv6(&domain, &route.ipv6()),
    };
    let operation = match planned {
        Ok(operation) => operation,
        Err(error) => {
            let failure = plan_failure(Words::Changes, locale, &error);
            return Ok(refused(action, failure).await);
        }
    };
    let mut outcome = action.run_planned(removal(&operation, route)).await;
    let report = outcome.take_report();
    let refreshed = static_region(
        &domain,
        (&router, family),
        &shown_query(&headers),
        (true, locale),
    )
    .await
    .ok()
    .and_then(|region| rendered(&region.out_of_band()));
    match report {
        None | Some(Report::Note(_)) => Ok(answer(outcome, refreshed, locale)),
        Some(Report::RouteCountMismatch) => {
            let message = tr(locale, keys::WEB_ROUTING_COUNT_MISMATCH, None);
            let shown = Outcome::failed(Failure::new(message, "route_count_mismatch"));
            Ok(answer(shown, refreshed, locale))
        }
        Some(Report::RoutesWiped { unsaved }) => {
            let after = read_static(&domain, family).await.unwrap_or_default();
            let guard = Guard::new(&before, &after, unsaved);
            Record::on_router(
                "web.routing_route_wipe",
                &router,
                family.command().to_owned(),
            )
            .append(&state, &user, guard.audit())
            .await;
            Ok(guarded(outcome, Some(guard), refreshed, locale))
        }
    }
}
