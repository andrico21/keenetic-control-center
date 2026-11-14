//! Remove route: a plain confirmation, then the removal through the route-wipe guard.
//!
//! When the router answers a single removal by clearing every static route, the routing
//! domain puts back each route the router had just before and stops; the page reads the
//! routes back and says so prominently, naming what came back or what did not.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_app::workflow::WorkflowError;
use kcc_catalog::Risk;
use kcc_domain::{DomainError, routing::change};
use kcc_i18n::{bundle::tr, keys};
use serde::Deserialize;

use super::{
    frame::workflow_error,
    guard::Guard,
    reply::{ConfirmDialog, answer, gone, guarded, unread},
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
        outcome::{Failure, Outcome},
        request::{missing, rendered, shown_query, with_query},
        respond::Answer,
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

/// How the guarded removal ended beyond the kit's outcome.
#[derive(Debug, Clone, Copy, Default)]
enum Ending {
    /// As the kit says.
    #[default]
    Plain,
    /// The router cleared every route; whether it has unsaved changes now.
    Wiped(bool),
    /// The routing table did not lose exactly one route.
    Miscounted,
}

/// `POST /ui/r/{router}/routing/route/remove?...`: removes the route through the
/// route-wipe guard and answers with its outcome, the guard's banner when it acted, and
/// the routes read back.
///
/// # Errors
///
/// Answers 404 for a malformed route, and what the kit answers when the router or the
/// permission is missing.
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
        Err(message) => return Ok(unread(action, message).await),
    };
    if !before.contains(&route) {
        return Ok(gone(action).await);
    }
    let mut ending = Ending::Plain;
    let outcome = action
        .run_with(Risk::Write, async |changes, context| {
            let removed = match family {
                Family::V4 => change::remove_ipv4(changes, context, &route.ipv4()).await,
                Family::V6 => change::remove_ipv6(changes, context, &route.ipv6()).await,
            };
            let failed = |field: &str| WorkflowError::VerificationFailed {
                field: field.to_owned(),
            };
            match removed {
                Ok(result) => Ok(Applied::Cli {
                    unsaved: result.unsaved,
                    responses: result.responses,
                }),
                Err(DomainError::SafetyAbort) => {
                    let last = changes.current_last_change().await;
                    ending = Ending::Wiped(last.map_or(true, |found| found.unsaved));
                    Err(failed(family.command()))
                }
                Err(DomainError::RouteCountMismatch) => {
                    ending = Ending::Miscounted;
                    Err(failed(family.command()))
                }
                Err(other) => Err(workflow_error(other)),
            }
        })
        .await;
    let refreshed = static_region(
        &domain,
        (&router, family),
        &shown_query(&headers),
        (true, locale),
    )
    .await
    .ok()
    .and_then(|region| rendered(&region.out_of_band()));
    match ending {
        Ending::Plain => Ok(answer(outcome, refreshed, locale)),
        Ending::Miscounted => {
            let message = tr(locale, keys::WEB_ROUTING_COUNT_MISMATCH, None);
            let shown = Outcome::failed(Failure::new(message, "route_count_mismatch"));
            Ok(answer(shown, refreshed, locale))
        }
        Ending::Wiped(unsaved) => {
            let after = read_static(&domain, family).await;
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
