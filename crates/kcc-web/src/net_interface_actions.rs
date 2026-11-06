//! Enable and Disable on the interfaces page, and the parser lines of every interface
//! change.
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
use kcc_app::workflow::{CliChangeRequest, CliCommand as ValidatedCli};
use kcc_catalog::Risk;
use kcc_domain::{ChangeOp, DomainError, interfaces};
use kcc_rci::ObjectName;
use serde_json::{Value, json};

use crate::{
    WebState,
    authz::CurrentUser,
    net_change::{Params, Planned, finish, missing, with_query},
    net_interface_line::Level,
    net_pages::Call,
    page_kit::{action::Operation, confirm::Resubmit, respond::Answer},
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
            let domain = action.context().await?;
            let change = interfaces::plan_up(&domain, &name)
                .and_then(|operation| Ok((cli_request(&name, &operation)?, operation.risk)));
            Ok(finish(call, action, Planned::new(domain, change)).await)
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
// NOT cancel-safe: see `Action::run`.
async fn disable(call: Call<'_>, name: &ObjectName, params: &Params) -> Result<Response, Answer> {
    let action = DOWN.open(call.state(), call.user(), call.router()).await?;
    let resubmit = Resubmit::new(
        with_query(
            &format!("/ui/r/{}/network/state", call.router()),
            &[("name", name.as_str()), ("state", "down")],
        ),
        "#page-outcome",
    );
    if let Some(prompt) = action.confirm(Risk::Management, &params.confirmation(), resubmit) {
        return Ok(prompt);
    }
    let domain = action.context().await?;
    let change = match interfaces::detect_management(&domain, name).await {
        Ok(verdict) => interfaces::plan_down(&domain, name, verdict)
            .and_then(|operation| Ok((cli_request(name, &operation)?, operation.risk))),
        Err(error) => Err(error),
    };
    Ok(finish(call, action, Planned::new(domain, change)).await)
}

/// The protected parser request of an interface plan.
///
/// kcc-domain converts these plans only inside its guarded `interfaces::apply`, which arms
/// a second fail-safe timer inside the one the kit arms and reports failures without the
/// router's words; the page renders the same closed set of lines and runs them through
/// the kit instead.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] for a plan outside that set.
pub(crate) fn cli_request(
    name: &ObjectName,
    operation: &ChangeOp,
) -> Result<CliChangeRequest, DomainError> {
    let validated = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let value = &validated.value;
    let line = match validated.path.as_str() {
        "interface up" if value.get("no") == Some(&Value::Bool(true)) => {
            format!("interface {name} down")
        }
        "interface up" => format!("interface {name} up"),
        "interface description" => {
            let text = value
                .get("description")
                .and_then(Value::as_str)
                .ok_or(DomainError::InvalidResponse)?;
            let quoted =
                serde_json::to_string(text).map_err(|_error| DomainError::InvalidResponse)?;
            format!("interface {name} description {quoted}")
        }
        "interface security-level" => {
            let level = Level::ALL
                .into_iter()
                .find(|level| value.get(level.slug()) == Some(&Value::Bool(true)))
                .ok_or(DomainError::InvalidResponse)?;
            format!("interface {name} security-level {}", level.slug())
        }
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(CliChangeRequest::new(
        vec![ValidatedCli::new(line, validated.clone())],
        operation.verify.clone(),
        operation.permission,
        json!({"operation": validated.path, "interface": name.as_str()}),
    ))
}
