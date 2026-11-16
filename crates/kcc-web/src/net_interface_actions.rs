//! Enable and Disable on the interfaces page.
//!
//! Disabling an interface can cut kcc off from the router: it asks first, with the
//! fail-safe explanation and before kcc reads anything, then plans with the management
//! verdict kcc detects and runs inside the router's fail-safe timer, which the kit arms
//! and disarms.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_catalog::Risk;
use kcc_domain::interfaces;
use kcc_rci::ObjectName;

use crate::{
    WebState,
    authz::CurrentUser,
    net_change::refreshed,
    net_pages::Call,
    page_kit::{
        action::Operation,
        change::Change,
        confirm::Resubmit,
        request::{Params, missing, with_query},
        respond::Answer,
        submit::{Formless, Planned, Submission},
    },
};

/// Enabling an interface, audited as `web.interface_up`.
const UP: Operation = Operation::write(&interfaces::DESCRIPTOR, "up", "web.interface_up");

/// Disabling an interface, audited as `web.interface_down`.
const DOWN: Operation = Operation::write(&interfaces::DESCRIPTOR, "down", "web.interface_down");

/// `POST /ui/r/{router}/network/state?name=&state=up|down`: Enable, or Disable after the
/// fail-safe confirmation.
///
/// # Errors
///
/// Answers 404 for a missing interface name or state, and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn state(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let params = Params::new(query, form);
    let name = params.object("name")?;
    let call = Call::new(&state, &user, &router, &headers);
    match params.get("state") {
        Some("up") => {
            let action = UP.open(&state, &user, &router).await?;
            let resubmit = Resubmit::new(
                params.again(&format!("/ui/r/{router}/network/state")),
                "#page-outcome",
            );
            Ok(Submission::new(action, &params, Formless, resubmit)
                .submit(
                    |_params| Ok(()),
                    async |(), domain| {
                        let operation = interfaces::plan_up(domain, &name)?;
                        let request = interfaces::change_request(&name, &operation)?;
                        Ok(Planned::of(&[operation], Change::Cli(request)))
                    },
                    async |domain| refreshed(call, domain).await,
                )
                .await)
        }
        Some("down") => disable(call, &name, &params).await,
        Some(_) | None => Err(missing()),
    }
}

/// Disables `name` once confirmed: detects whether it carries kcc's connection, plans with
/// that verdict and runs inside the fail-safe timer.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
// NOT cancel-safe: see `Submission::submit`.
async fn disable(call: Call<'_>, name: &ObjectName, params: &Params) -> Result<Response, Answer> {
    let action = DOWN.open(call.state(), call.user(), call.router()).await?;
    let resubmit = Resubmit::new(
        with_query(
            &format!("/ui/r/{}/network/state", call.router()),
            &[("name", name.as_str()), ("state", "down")],
        ),
        "#page-outcome",
    );
    Ok(Submission::new(action, params, Formless, resubmit)
        .confirming(Risk::Management)
        .submit(
            |_params| Ok(()),
            async |(), domain| {
                let verdict = interfaces::detect_management(domain, name).await?;
                let operation = interfaces::plan_down(domain, name, verdict)?;
                let request = interfaces::change_request(name, &operation)?;
                Ok(Planned::of(&[operation], Change::Cli(request)))
            },
            async |domain| refreshed(call, domain).await,
        )
        .await)
}
