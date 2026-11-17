//! Catalog-validated connection-policy plans.

use alloc::vec;

use kcc_app::permissions::Permission;
use kcc_catalog::{Risk, ValidatedRequest};
use serde_json::{Map, Value, json};

use super::super::model::{PolicyPermit, PolicyRateLimit, PolicyRoute};
use crate::{ChangeOp, DomainError, Result, RouterCtx, planning::validate};

/// Plans creation of an empty connection policy.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn create(router: &RouterCtx, name: &str) -> Result<ChangeOp> {
    context_plan(router, name, false)
}

/// Plans removal of one connection policy.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn remove(router: &RouterCtx, name: &str) -> Result<ChangeOp> {
    context_plan(router, name, true)
}

/// Plans setting or clearing a policy description.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn description(router: &RouterCtx, name: &str, description: Option<&str>) -> Result<ChangeOp> {
    let body = description.map_or_else(|| json!({"no":true}), |value| json!({"description":value}));
    leaf_plan(router, name, "ip policy description", &body)
}

/// Plans adding or removing a permitted interface.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]), or when a reply or a plan does not have the expected
/// shape ([`DomainError::InvalidResponse`]).
#[inline]
pub fn permit(
    router: &RouterCtx,
    name: &str,
    permit: &PolicyPermit,
    enabled: bool,
) -> Result<ChangeOp> {
    let mut body = json!({"interface":permit.interface});
    let fields = body.as_object_mut().ok_or(DomainError::InvalidResponse)?;
    insert_optional_number(fields, "order", permit.order);
    insert_removal(fields, enabled);
    leaf_plan(router, name, "ip policy permit", &body)
}

/// Plans enabling or disabling policy multipath routing.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn multipath(router: &RouterCtx, name: &str, enabled: bool) -> Result<ChangeOp> {
    leaf_plan(router, name, "ip policy multipath", &toggle(enabled))
}

/// Plans adding or removing one policy-owned IPv4 route.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]), or when a reply or a plan does not have the expected
/// shape ([`DomainError::InvalidResponse`]).
#[inline]
pub fn route(
    router: &RouterCtx,
    name: &str,
    route: &PolicyRoute,
    enabled: bool,
) -> Result<ChangeOp> {
    let mut body = route.mask.as_ref().map_or_else(
        || json!({"host":route.destination}),
        |mask| json!({"network":route.destination,"mask":mask}),
    );
    let fields = body.as_object_mut().ok_or(DomainError::InvalidResponse)?;
    insert_optional_text(fields, "gateway", route.gateway.as_ref());
    insert_optional_text(fields, "interface", route.interface.as_ref());
    insert_optional_number(fields, "metric", route.metric);
    insert_removal(fields, enabled);
    leaf_plan(router, name, "ip policy route", &body)
}

/// Plans setting or removing one interface rate limit.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]), or when a reply or a plan does not have the expected
/// shape ([`DomainError::InvalidResponse`]).
#[inline]
pub fn rate_limit(
    router: &RouterCtx,
    name: &str,
    limit: &PolicyRateLimit,
    enabled: bool,
) -> Result<ChangeOp> {
    let mut body = json!({"interface":limit.interface});
    let fields = body.as_object_mut().ok_or(DomainError::InvalidResponse)?;
    insert_optional_number(fields, "rate", limit.rate);
    insert_removal(fields, enabled);
    leaf_plan(
        router,
        name,
        &format!("ip policy rate-limit {}", limit.direction.name()),
        &body,
    )
}

/// Plans enabling or disabling standalone policy operation.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn standalone(router: &RouterCtx, name: &str, enabled: bool) -> Result<ChangeOp> {
    leaf_plan(router, name, "ip policy standalone", &toggle(enabled))
}

/// Plans creating or removing the policy context `name`.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] when the catalog refuses the request.
fn context_plan(router: &RouterCtx, name: &str, remove: bool) -> Result<ChangeOp> {
    let body = if remove {
        json!({"name":name,"no":true})
    } else {
        json!({"name":name})
    };
    Ok(operation(vec![validate(router, "ip policy", &body)?]))
}

/// Plans `path` with `body` under the policy context `name`.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] when the catalog refuses a request.
fn leaf_plan(router: &RouterCtx, name: &str, path: &str, body: &Value) -> Result<ChangeOp> {
    let context = validate(router, "ip policy", &json!({"name":name}))?;
    let leaf = validate(router, path, body)?;
    Ok(operation(vec![context, leaf]))
}

/// A policy plan of `requests`: write risk, needing `Write`.
const fn operation(requests: Vec<ValidatedRequest>) -> ChangeOp {
    ChangeOp::new(requests, Vec::new(), Risk::Write, Permission::Write, false)
}

/// The body of a toggle: empty to enable, `no` to disable.
fn toggle(enabled: bool) -> Value {
    if enabled {
        json!({})
    } else {
        json!({"no":true})
    }
}

/// Inserts `no` when the setting is disabled.
fn insert_removal(fields: &mut Map<String, Value>, enabled: bool) {
    if !enabled {
        drop(fields.insert("no".to_owned(), Value::Bool(true)));
    }
}

/// Inserts the text `value` as `name` when it is given.
fn insert_optional_text(fields: &mut Map<String, Value>, name: &str, value: Option<&String>) {
    if let Some(text) = value {
        drop(fields.insert(name.to_owned(), Value::String(text.clone())));
    }
}

/// Inserts the number `value` as `name` when it is given.
fn insert_optional_number(fields: &mut Map<String, Value>, name: &str, value: Option<u32>) {
    if let Some(number) = value {
        drop(fields.insert(name.to_owned(), json!(number)));
    }
}
