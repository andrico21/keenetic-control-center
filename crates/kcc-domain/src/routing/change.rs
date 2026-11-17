//! Catalog-validated route mutation and wipe recovery.

use alloc::vec;

use kcc_app::workflow::{
    ChangeSet, CliChangeRequest, CliChangeResult, CliCommand as ValidatedCli, WorkflowError,
};
use kcc_catalog::{Risk, ValidatedRequest};
use kcc_rci::RciBody;
use serde_json::{Value, json};

use super::model::{Ipv4Route, Ipv6Route};
use crate::{
    ChangeOp, DomainError, Result, RouterCtx,
    planning::plan_one,
    request_words::{field_word, negated, optional_text},
    verification,
};

mod ipv6;
mod restore;

/// Plans adding one catalog-validated IPv4 route.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_add_ipv4(router: &RouterCtx, route: &Ipv4Route) -> Result<ChangeOp> {
    plan_ipv4(router, route, false)
}

/// Plans removing one IPv4 route without executing the protected workflow.
///
/// Execute removals through [`remove_ipv4`] so broad clears are restored and the
/// removal is verified.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_remove_ipv4(router: &RouterCtx, route: &Ipv4Route) -> Result<ChangeOp> {
    plan_ipv4(router, route, true)
}

/// Plans adding one catalog-validated IPv6 route.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_add_ipv6(router: &RouterCtx, route: &Ipv6Route) -> Result<ChangeOp> {
    plan_ipv6(router, route, false)
}

/// Plans removing one IPv6 route without executing the protected workflow.
///
/// Execute removals through [`remove_ipv6`] so broad clears are restored and the
/// removal is verified.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_remove_ipv6(router: &RouterCtx, route: &Ipv6Route) -> Result<ChangeOp> {
    plan_ipv6(router, route, true)
}

/// Converts a route plan into protected CLI workflow input.
///
/// # Errors
///
/// Returns an error when the plan holds no request or its read-back cannot be built
/// ([`DomainError::InvalidResponse`]), or when the rendered line does not bind to its
/// request ([`DomainError::Workflow`]).
#[inline]
pub fn request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let validated = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    verification::complete(CliChangeRequest::new(
        vec![ValidatedCli::new(render(validated), validated.clone())?],
        Vec::new(),
        operation.permission,
        json!({"domain":"routing"}),
    ))
}

/// Removes one IPv4 route and verifies the exact command is gone from the running
/// configuration; a broad-clear status restores every saved static route and aborts.
///
/// # Errors
///
/// Returns an error when reading the saved routes fails or does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]), when the catalog refuses a
/// planned request ([`DomainError::Validation`]), when the removal cannot be rendered or
/// given a read-back ([`DomainError::InvalidResponse`]), when the change workflow fails in
/// dispatch or audit, or a rendered line does not bind to its request
/// ([`DomainError::Workflow`]), or when the read-back still finds the route
/// ([`DomainError::RouteCountMismatch`]). When the router reports a broad clear, the first
/// failure of restoring the saved routes is returned, or [`DomainError::SafetyAbort`] when
/// it succeeded.
// NOT cancel-safe: cancelled after the removal is sent, the route (or, on a broad clear,
// every static route not yet restored) stays removed and unverified.
#[inline]
pub async fn remove_ipv4(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    route: &Ipv4Route,
) -> Result<CliChangeResult> {
    let saved = restore::saved_ipv4(router).await?;
    let removal = plan_remove_ipv4(router, route)?;
    let result = match changes.apply_cli(request(&removal)?).await {
        Ok(result) => result,
        Err(WorkflowError::VerificationFailed { field: _ }) => {
            return Err(DomainError::RouteCountMismatch);
        }
        Err(error) => return Err(error.into()),
    };
    if reports_cleared(&result.responses) {
        return Err(restore::restore_ipv4(changes, router, saved).await);
    }
    Ok(result)
}

/// Removes one IPv6 route, restoring every saved static route and aborting on a broad-clear
/// status.
///
/// # Errors
///
/// Returns [`DomainError::Rci`] or [`DomainError::InvalidResponse`] when reading the saved routes
/// fails, [`DomainError::Validation`] when the catalog refuses the removal,
/// [`DomainError::InvalidResponse`] when the removal cannot be rendered or given a read-back,
/// [`DomainError::Workflow`] when the change workflow fails in dispatch or audit, and
/// [`DomainError::RouteCountMismatch`] when the read-back still finds the route. When the router
/// reports a broad clear, every saved route is re-added and the first failure of that restore is
/// returned, or [`DomainError::SafetyAbort`] when it succeeded.
// NOT cancel-safe: cancelled after the removal is sent, the route (or, on a broad clear,
// every static route not yet restored) stays removed and unverified.
#[inline]
pub async fn remove_ipv6(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    route: &Ipv6Route,
) -> Result<CliChangeResult> {
    ipv6::remove(changes, router, route).await
}

/// Plans adding or removing one IPv4 static route.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] when the catalog refuses the request.
fn plan_ipv4(router: &RouterCtx, route: &Ipv4Route, remove: bool) -> Result<ChangeOp> {
    let mut body = if route.destination == "default" {
        json!({})
    } else if let Some(mask) = &route.mask {
        json!({"network":route.destination,"mask":mask})
    } else {
        json!({"host":route.destination})
    };
    let fields = body.as_object_mut().ok_or(DomainError::InvalidResponse)?;
    insert_optional(fields, "gateway", route.gateway.as_ref());
    insert_optional(fields, "interface", route.interface.as_ref());
    if let Some(metric) = route.metric {
        drop(fields.insert("metric".to_owned(), json!(metric)));
    }
    if remove {
        drop(fields.insert("no".to_owned(), json!(true)));
    }
    plan_one(router, "ip route", &body, Risk::Write)
}

/// Plans adding or removing one IPv6 static route.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] when the catalog refuses the request.
fn plan_ipv6(router: &RouterCtx, route: &Ipv6Route, remove: bool) -> Result<ChangeOp> {
    let mut body = if route.prefix == "default" {
        json!({})
    } else {
        json!({"prefix":route.prefix})
    };
    let fields = body.as_object_mut().ok_or(DomainError::InvalidResponse)?;
    insert_optional(fields, "gateway", route.gateway.as_ref());
    insert_optional(fields, "interface", route.interface.as_ref());
    if remove {
        drop(fields.insert("no".to_owned(), json!(true)));
    }
    plan_one(router, "ipv6 route", &body, Risk::Write)
}

/// Inserts `value` as `name` when it is given.
fn insert_optional(
    fields: &mut serde_json::Map<String, Value>,
    name: &str,
    value: Option<&String>,
) {
    if let Some(item) = value {
        drop(fields.insert(name.to_owned(), json!(item)));
    }
}

/// The CLI line of one validated route request.
fn render(request: &ValidatedRequest) -> String {
    let value = request.value();
    let mut parts = vec![request.path.clone()];
    if request.path == "ip route" {
        if let (Some(network), Some(mask)) = (
            optional_text(request, "network"),
            optional_text(request, "mask"),
        ) {
            parts.extend([network.to_owned(), mask.to_owned()]);
        } else if let Some(host) = optional_text(request, "host") {
            parts.push(host.to_owned());
        } else {
            parts.push("default".to_owned());
        }
    } else if let Some(prefix) = optional_text(request, "prefix") {
        parts.push(prefix.to_owned());
    } else {
        parts.push("default".to_owned());
    }
    // `ip route` names the gateway first; `ipv6 route` names the interface first.
    let fields = if request.path == "ip route" {
        ["gateway", "interface", "metric"]
    } else {
        ["interface", "gateway", "metric"]
    };
    for field in fields {
        parts.extend(field_word(value, field));
    }
    negated(value, parts.join(" "))
}

/// Whether a router reply reports that routes were cleared.
fn reports_cleared(responses: &[RciBody]) -> bool {
    responses.iter().any(|body| match body {
        RciBody::Json(response) => response
            .statuses
            .iter()
            .any(|(_pointer, item)| item.message.to_ascii_lowercase().contains("cleared")),
        RciBody::Text(_) | _ => false,
    })
}
