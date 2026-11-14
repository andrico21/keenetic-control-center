//! Add route: the dialog, its checks, the plan and the read-back.
//!
//! An IPv4 route goes to a network and mask, an IPv6 route to a prefix, through a gateway,
//! an interface or both; the routing domain plans it and the routing table reads it back.

use core::slice;

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_app::workflow::{CliChangeRequest, WorkflowError};
use kcc_domain::{
    ChangeOp, RouterCtx,
    routing::{change, descriptor::DESCRIPTOR, read},
};
use kcc_i18n::keys;
use serde::Deserialize;

use super::{
    frame::{interface_names, workflow_error},
    reply::Replying,
    route_form::{check, destination_field, form},
    route_rows::{Family, StaticRoute, static_routes},
    route_views::{read_table, static_region},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        change::Applied,
        request::{Params, missing, rendered, shown_query},
        respond::Answer,
        submit::{Invalid, Planned, Submission},
    },
};

/// The family a route action names.
#[derive(Debug, Deserialize)]
pub(crate) struct FamilyQuery {
    /// `ipv4` (the default) or `ipv6`.
    #[serde(default)]
    family: Option<String>,
}

impl FamilyQuery {
    /// The family named, or 404.
    ///
    /// # Errors
    ///
    /// Answers 404 for an unknown family.
    pub(crate) fn family(&self) -> Result<Family, Answer> {
        Family::from_slug(self.family.as_deref()).ok_or_else(missing)
    }
}

/// The route write of `family`, audited as `action`.
pub(crate) const fn operation(family: Family, action: &'static str) -> Operation {
    Operation::write(&DESCRIPTOR, family.operation(), action)
}

/// `GET /ui/r/{router}/routing/route/new?family=`: the Add route dialog.
///
/// # Errors
///
/// Answers 404 for an unknown family, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<FamilyQuery>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let family = query.family()?;
    let action = operation(family, "web.routing_route_add")
        .open(&state, &user, &router)
        .await?;
    let domain = action.context().await?;
    let names = interface_names(&domain).await;
    Ok(form(
        action.locale(),
        (&router, family),
        &Params::default(),
        &names,
    )
    .show())
}

/// `POST /ui/r/{router}/routing/route/new?family=`: checks the route, adds it and reads
/// it back from the routing table.
///
/// # Errors
///
/// Answers the dialog with its field errors (422), 404 for an unknown family, and what
/// the kit answers when the router or the permission is missing.
pub(crate) async fn add(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<FamilyQuery>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let family = query.family()?;
    let action = operation(family, "web.routing_route_add")
        .open(&state, &user, &router)
        .await?;
    let locale = action.locale();
    let values = Params::new(Vec::new(), pairs);
    let names = interface_names(&action.context().await?).await;
    let dialog = Replying::new(form(locale, (&router, family), &values, &names));
    Ok(Submission::new(action, &values, dialog)
        .submit_reading(
            async |submitted, domain| {
                let route = check(family, submitted, &names)
                    .map_err(|(field, rule)| Invalid::at(field, rule))?;
                if read_static(domain, family).await.contains(&route) {
                    let field = destination_field(family);
                    return Err(Invalid::at(field, keys::WEB_ROUTING_ERROR_DUPLICATE).into());
                }
                Ok(route)
            },
            async |route, domain| {
                let operation = match family {
                    Family::V4 => change::plan_add_ipv4(domain, &route.ipv4()),
                    Family::V6 => change::plan_add_ipv6(domain, &route.ipv6()),
                }?;
                let request = change::request(&operation)?;
                Ok(added(&operation, route, request))
            },
            async |domain| {
                static_region(
                    domain,
                    (&router, family),
                    &shown_query(&headers),
                    (true, locale),
                )
                .await
                .ok()
                .and_then(|region| rendered(&region.out_of_band()))
            },
        )
        .await)
}

/// `operation`, adding `route` with `request` and reading it back from the routing table.
fn added(operation: &ChangeOp, route: StaticRoute, request: CliChangeRequest) -> Planned {
    let family = route.family();
    Planned::working(slice::from_ref(operation), move |changes, domain| {
        Box::pin(async move {
            let result = changes.apply_cli(request).await?;
            let table = match family {
                Family::V4 => read::ipv4_table(domain).await,
                Family::V6 => read::ipv6_table(domain).await,
            }
            .map_err(workflow_error)?;
            if static_routes(family, &table).contains(&route) {
                Ok(Applied::Cli {
                    unsaved: result.unsaved,
                    responses: result.responses,
                })
            } else {
                Err(WorkflowError::VerificationFailed {
                    field: family.command().to_owned(),
                })
            }
        })
    })
}

/// The static routes of `family` the router has now; none when it does not answer.
// cancel-safe: reads only.
pub(crate) async fn read_static(domain: &RouterCtx, family: Family) -> Vec<StaticRoute> {
    read_table(domain, family)
        .await
        .map(|entries| static_routes(family, &entries))
        .unwrap_or_default()
}
