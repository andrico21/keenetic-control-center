//! Catalog-validated firewall planning and fresh-read execution.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "protected mutations are not inline candidates"
)]
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private render helpers are narrowly named"
    )
)]

use alloc::{format, vec};

use kcc_app::{
    permissions::Permission,
    workflow::{ChangeSet, CliChangeRequest, CliChangeResult, CliCommand as ValidatedCli},
};
use kcc_catalog::{HttpMethod, Risk, ValidatedRequest};
use serde_json::{Map, Value, json};

use super::{
    model::{Direction, Rule},
    read,
};
use crate::{ChangeOp, DomainError, Result, RouterCtx};

/// Plans adding one access-list rule.
pub fn plan_add_rule(router: &RouterCtx, name: &str, rule: &Rule) -> Result<ChangeOp> {
    plan_rule(router, name, rule, false)
}

/// Plans removing exactly one access-list rule.
pub fn plan_remove_rule(router: &RouterCtx, name: &str, rule: &Rule) -> Result<ChangeOp> {
    plan_rule(router, name, rule, true)
}

/// Plans one rule order, description, disable, or schedule property.
pub fn plan_rule_property(
    router: &RouterCtx,
    name: &str,
    index: u32,
    property: RuleProperty<'_>,
) -> Result<ChangeOp> {
    let body = match property {
        RuleProperty::Description(value) => json!({"index":index,"description":value}),
        RuleProperty::Disable => json!({"index":index}),
        RuleProperty::Schedule(value) => json!({"index":index,"schedule":value}),
    };
    contextual(router, name, "access-list rule", &body)
}

/// Rule metadata property.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RuleProperty<'value> {
    /// Human-readable rule description.
    Description(&'value str),
    /// Disable the indexed rule.
    Disable,
    /// Apply a named schedule.
    Schedule(&'value str),
}

/// Plans binding an IPv4 access list to an interface.
pub fn plan_bind(
    router: &RouterCtx,
    interface: &str,
    acl: &str,
    direction: Direction,
    enabled: bool,
) -> Result<ChangeOp> {
    let context = validate(router, "interface", &json!({"name":interface}))?;
    let mut body = json!({"acl":acl,"direction":direction.name()});
    if !enabled {
        insert(
            body.as_object_mut().ok_or(DomainError::InvalidResponse)?,
            "no",
            json!(true),
        );
    }
    let leaf = validate(router, "interface ip access-group", &body)?;
    Ok(operation(vec![context, leaf]))
}

/// Applies a firewall plan and verifies its positive CLI line in a fresh running configuration.
pub async fn apply(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    operation: &ChangeOp,
) -> Result<CliChangeResult> {
    let line = render(operation)?;
    let validated = operation
        .requests
        .last()
        .ok_or(DomainError::InvalidResponse)?;
    let result = changes
        .apply_cli(CliChangeRequest::new(
            vec![ValidatedCli::new(line.clone(), validated.clone())],
            Vec::new(),
            operation.permission,
            json!({"domain":"firewall"}),
        ))
        .await?;
    let running = read::access_lists(router).await?;
    let present = running.to_string().contains(
        line.trim_start_matches("no ")
            .split_whitespace()
            .last()
            .ok_or(DomainError::InvalidResponse)?,
    );
    let removing = line.starts_with("no ");
    if present == removing {
        return Err(DomainError::InvalidResponse);
    }
    Ok(result)
}

fn plan_rule(router: &RouterCtx, name: &str, rule: &Rule, remove: bool) -> Result<ChangeOp> {
    let mut body = json!({"source":rule.source,"source-mask":rule.source_mask,"destination":rule.destination,"destination-mask":rule.destination_mask});
    let fields = body.as_object_mut().ok_or(DomainError::InvalidResponse)?;
    if let Some(port) = rule.source_port {
        insert(fields, "src-port-operator", json!("eq"));
        insert(fields, "source-port", json!(port));
    }
    if let Some(port) = rule.destination_port {
        insert(fields, "dst-port-operator", json!("eq"));
        insert(fields, "destination-port", json!(port));
    }
    if remove {
        insert(fields, "no", json!(true));
    }
    contextual(
        router,
        name,
        &format!("access-list {}", rule.action.name()),
        &body,
    )
}

fn contextual(router: &RouterCtx, name: &str, path: &str, body: &Value) -> Result<ChangeOp> {
    Ok(operation(vec![
        validate(router, "access-list", &json!({"name":name}))?,
        validate(router, path, body)?,
    ]))
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

fn render(operation: &ChangeOp) -> Result<String> {
    let [context, leaf] = operation.requests.as_slice() else {
        return Err(DomainError::InvalidResponse);
    };
    let name = context
        .value
        .get("name")
        .and_then(Value::as_str)
        .ok_or(DomainError::InvalidResponse)?;
    let mut words = if context.path == "interface" {
        vec![
            "interface".to_owned(),
            name.to_owned(),
            "ip".to_owned(),
            "access-group".to_owned(),
        ]
    } else {
        vec![
            "access-list".to_owned(),
            name.to_owned(),
            leaf.path
                .strip_prefix("access-list ")
                .ok_or(DomainError::InvalidResponse)?
                .to_owned(),
        ]
    };
    for field in [
        "source",
        "source-mask",
        "source-port",
        "destination",
        "destination-mask",
        "destination-port",
        "index",
        "description",
        "schedule",
        "acl",
        "direction",
    ] {
        if let Some(value) = leaf.value.get(field) {
            words.push(
                value
                    .as_str()
                    .map_or_else(|| value.to_string(), ToOwned::to_owned),
            );
        }
    }
    let line = words.join(" ");
    Ok(if leaf.value.get("no") == Some(&Value::Bool(true)) {
        format!("no {line}")
    } else {
        line
    })
}

fn insert(fields: &mut Map<String, Value>, name: &str, value: Value) {
    drop(fields.insert(name.to_owned(), value));
}
