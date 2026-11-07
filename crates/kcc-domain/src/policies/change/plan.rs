//! Catalog-validated connection-policy plans.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "policy planning is not an inline candidate"
)]
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private validation and body assembly helpers are named after their policy role"
    )
)]

use alloc::vec;

use kcc_app::permissions::Permission;
use kcc_catalog::{HttpMethod, Risk, ValidatedRequest};
use serde_json::{Map, Value, json};

use super::super::model::{PolicyPermit, PolicyRateLimit, PolicyRoute};
use crate::{ChangeOp, DomainError, Result, RouterCtx};

/// Plans creation of an empty connection policy.
pub fn create(router: &RouterCtx, name: &str) -> Result<ChangeOp> {
    context_plan(router, name, false)
}

/// Plans removal of one connection policy.
pub fn remove(router: &RouterCtx, name: &str) -> Result<ChangeOp> {
    context_plan(router, name, true)
}

/// Plans setting or clearing a policy description.
pub fn description(router: &RouterCtx, name: &str, description: Option<&str>) -> Result<ChangeOp> {
    let body = description.map_or_else(|| json!({"no":true}), |value| json!({"description":value}));
    leaf_plan(router, name, "ip policy description", &body)
}

/// Plans adding or removing a permitted interface.
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
pub fn multipath(router: &RouterCtx, name: &str, enabled: bool) -> Result<ChangeOp> {
    leaf_plan(router, name, "ip policy multipath", &toggle(enabled))
}

/// Plans adding or removing one policy-owned IPv4 route.
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
pub fn standalone(router: &RouterCtx, name: &str, enabled: bool) -> Result<ChangeOp> {
    leaf_plan(router, name, "ip policy standalone", &toggle(enabled))
}

fn context_plan(router: &RouterCtx, name: &str, remove: bool) -> Result<ChangeOp> {
    let body = if remove {
        json!({"name":name,"no":true})
    } else {
        json!({"name":name})
    };
    Ok(operation(vec![validate(router, "ip policy", &body)?]))
}

fn leaf_plan(router: &RouterCtx, name: &str, path: &str, body: &Value) -> Result<ChangeOp> {
    let context = validate(router, "ip policy", &json!({"name":name}))?;
    let leaf = validate(router, path, body)?;
    Ok(operation(vec![context, leaf]))
}

fn validate(router: &RouterCtx, path: &str, body: &Value) -> Result<ValidatedRequest> {
    router
        .catalog
        .validate(path, HttpMethod::Post, body)
        .map_err(|issues| DomainError::Validation { issues })
}

const fn operation(requests: Vec<ValidatedRequest>) -> ChangeOp {
    ChangeOp::new(requests, Vec::new(), Risk::Write, Permission::Write, false)
}

fn toggle(enabled: bool) -> Value {
    if enabled {
        json!({})
    } else {
        json!({"no":true})
    }
}

fn insert_removal(fields: &mut Map<String, Value>, enabled: bool) {
    if !enabled {
        drop(fields.insert("no".to_owned(), Value::Bool(true)));
    }
}

fn insert_optional_text(fields: &mut Map<String, Value>, name: &str, value: Option<&String>) {
    if let Some(text) = value {
        drop(fields.insert(name.to_owned(), Value::String(text.clone())));
    }
}

fn insert_optional_number(fields: &mut Map<String, Value>, name: &str, value: Option<u32>) {
    if let Some(number) = value {
        drop(fields.insert(name.to_owned(), json!(number)));
    }
}
