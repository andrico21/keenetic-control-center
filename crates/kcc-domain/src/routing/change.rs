//! Catalog-validated route mutation and wipe recovery.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "protected route mutations are not inline candidates"
)]
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private route rendering and validation helpers are named after their safety role"
    )
)]

use alloc::{format, vec};

use kcc_app::{
    permissions::Permission,
    workflow::{
        ChangeSet, CliChangeRequest, CliChangeResult, CliCommand as ValidatedCli, WorkflowError,
    },
};
use kcc_catalog::{HttpMethod, Risk, ValidatedRequest};
use kcc_rci::RciBody;
use serde_json::{Value, json};

use super::{
    model::{Ipv4Route, Ipv6Route, RouteTableEntry},
    read,
};
use crate::{ChangeOp, DomainError, Result, RouterCtx, verification};

mod ipv6;

/// Plans adding one catalog-validated IPv4 route.
pub fn plan_add_ipv4(router: &RouterCtx, route: &Ipv4Route) -> Result<ChangeOp> {
    plan_ipv4(router, route, false)
}

/// Plans removing one IPv4 route without executing the protected workflow.
///
/// Execute removals through [`remove_ipv4`] so broad clears are restored and the
/// route-count invariant is verified.
pub fn plan_remove_ipv4(router: &RouterCtx, route: &Ipv4Route) -> Result<ChangeOp> {
    plan_ipv4(router, route, true)
}

/// Plans adding one catalog-validated IPv6 route.
pub fn plan_add_ipv6(router: &RouterCtx, route: &Ipv6Route) -> Result<ChangeOp> {
    plan_ipv6(router, route, false)
}

/// Plans removing one IPv6 route without executing the protected workflow.
///
/// Execute removals through [`remove_ipv6`] so broad clears are restored and the
/// route-count invariant is verified.
pub fn plan_remove_ipv6(router: &RouterCtx, route: &Ipv6Route) -> Result<ChangeOp> {
    plan_ipv6(router, route, true)
}

/// Converts a route plan into protected CLI workflow input.
pub fn request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let validated = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    verification::complete(CliChangeRequest::new(
        vec![ValidatedCli::new(render(validated), validated.clone())],
        Vec::new(),
        operation.permission,
        json!({"domain":"routing"}),
    ))
}

/// Removes one IPv4 route, restoring it and aborting on any broad-clear status.
// NOT cancel-safe: cancelled after the removal is sent, the route (or, on a broad clear,
// every static route not yet restored) stays removed and unverified.
pub async fn remove_ipv4(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    route: &Ipv4Route,
) -> Result<CliChangeResult> {
    let before_table = read::ipv4_table(router).await?;
    let before = before_table.len();
    let removal = plan_remove_ipv4(router, route)?;
    let result = match changes.apply_cli(request(&removal)?).await {
        Ok(result) => result,
        Err(WorkflowError::VerificationFailed { field: _ }) => {
            return Err(DomainError::RouteCountMismatch);
        }
        Err(error) => return Err(error.into()),
    };
    if reports_cleared(&result.responses) {
        for saved in before_table.iter().filter_map(configured_ipv4_route) {
            let restore = plan_add_ipv4(router, &saved?)?;
            drop(changes.apply_cli(request(&restore)?).await?);
        }
        return Err(DomainError::SafetyAbort);
    }
    let after = read::ipv4_table(router).await?.len();
    if before.checked_sub(after) != Some(1) {
        return Err(DomainError::RouteCountMismatch);
    }
    Ok(result)
}

/// Removes one IPv6 route, restoring all static routes and aborting on a broad-clear status.
// NOT cancel-safe: cancelled after the removal is sent, the route (or, on a broad clear,
// every static route not yet restored) stays removed and unverified.
pub async fn remove_ipv6(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    route: &Ipv6Route,
) -> Result<CliChangeResult> {
    ipv6::remove(changes, router, route).await
}

fn configured_ipv4_route(entry: &RouteTableEntry) -> Option<Result<Ipv4Route>> {
    if entry.is_static != Some(true) {
        return None;
    }
    Some(match entry.command.as_slice() {
        [network, mask, gateway] => Ok(Ipv4Route::network(network, mask, gateway)),
        [network, mask, gateway, interface] => {
            Ok(Ipv4Route::network(network, mask, gateway).on_interface(interface))
        }
        [network, mask, gateway, interface, metric] => metric
            .parse::<u32>()
            .map(|value| {
                Ipv4Route::network(network, mask, gateway)
                    .on_interface(interface)
                    .with_metric(value)
            })
            .map_err(|_error| DomainError::InvalidResponse),
        _ => Err(DomainError::InvalidResponse),
    })
}

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
    plan(router, "ip route", &body)
}

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
    plan(router, "ipv6 route", &body)
}

fn insert_optional(
    fields: &mut serde_json::Map<String, Value>,
    name: &str,
    value: Option<&String>,
) {
    if let Some(item) = value {
        drop(fields.insert(name.to_owned(), json!(item)));
    }
}

fn plan(router: &RouterCtx, path: &str, body: &Value) -> Result<ChangeOp> {
    let validated = router
        .catalog
        .validate(path, HttpMethod::Post, body)
        .map_err(|issues| DomainError::Validation { issues })?;
    Ok(ChangeOp::new(
        vec![validated],
        Vec::new(),
        Risk::Write,
        Permission::Write,
        false,
    ))
}

fn render(request: &ValidatedRequest) -> String {
    let value = request.value();
    let mut parts = vec![request.path.clone()];
    if request.path == "ip route" {
        if let (Some(network), Some(mask)) = (text(value, "network"), text(value, "mask")) {
            parts.extend([network.to_owned(), mask.to_owned()]);
        } else if let Some(host) = text(value, "host") {
            parts.push(host.to_owned());
        } else {
            parts.push("default".to_owned());
        }
    } else if let Some(prefix) = text(value, "prefix") {
        parts.push(prefix.to_owned());
    } else {
        parts.push("default".to_owned());
    }
    for field in ["gateway", "interface", "metric"] {
        if let Some(item) = value.get(field) {
            parts.push(
                item.as_str()
                    .map_or_else(|| item.to_string(), ToOwned::to_owned),
            );
        }
    }
    let line = parts.join(" ");
    if value.get("no").and_then(Value::as_bool) == Some(true) {
        format!("no {line}")
    } else {
        line
    }
}

fn reports_cleared(responses: &[RciBody]) -> bool {
    responses.iter().any(|body| match body {
        RciBody::Json(response) => response
            .statuses
            .iter()
            .any(|(_pointer, item)| item.message.to_ascii_lowercase().contains("cleared")),
        RciBody::Text(_) | _ => false,
    })
}

fn text<'value>(value: &'value Value, field: &str) -> Option<&'value str> {
    value.get(field).and_then(Value::as_str)
}
