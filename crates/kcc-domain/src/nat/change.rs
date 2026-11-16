//! Catalog-validated NAT mutations with fresh configuration verification.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "protected mutations are not inline candidates"
)]
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private render and verification helpers are narrowly named"
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
    model::{ForwardTarget, PortForward},
    read,
};
use crate::{ChangeOp, DomainError, Result, RouterCtx, verification};

/// Plans adding one static forwarding rule.
pub fn plan_add_forward(router: &RouterCtx, rule: &PortForward) -> Result<ChangeOp> {
    plan_forward(router, rule, false)
}

/// Plans removing exactly one static forwarding rule.
pub fn plan_remove_forward(router: &RouterCtx, rule: &PortForward) -> Result<ChangeOp> {
    plan_forward(router, rule, true)
}

/// Plans enabling NAT on one interface.
pub fn plan_add_interface(router: &RouterCtx, interface: &str) -> Result<ChangeOp> {
    plan(router, "ip nat", &json!({"interface":interface}))
}

/// Plans disabling NAT on one interface.
pub fn plan_remove_interface(router: &RouterCtx, interface: &str) -> Result<ChangeOp> {
    plan(router, "ip nat", &json!({"interface":interface,"no":true}))
}

/// Applies a NAT plan and verifies the exact command against a fresh `show rc` read.
// NOT cancel-safe: cancelled after the CLI request is sent, the router stays changed
// and the read-back verification never runs.
pub async fn apply(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    operation: &ChangeOp,
) -> Result<CliChangeResult> {
    let validated = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let line = render(validated);
    let positive = line.strip_prefix("no ").unwrap_or(&line);
    let tail: Vec<String> = positive
        .split_whitespace()
        .skip(2)
        .map(ToOwned::to_owned)
        .collect();
    let result = changes
        .apply_cli(verification::complete(CliChangeRequest::new(
            vec![ValidatedCli::new(line.clone(), validated.clone())?],
            Vec::new(),
            operation.permission,
            json!({"domain":"nat"}),
        ))?)
        .await?;
    let rows = if validated.path == "ip static" {
        read::running_forwards(router).await?
    } else {
        read::interfaces(router).await?
    };
    let present = rows.iter().any(|row| {
        row.command == tail
            || row
                .interface
                .as_ref()
                .is_some_and(|interface| tail.first() == Some(interface) && tail.len() == 1)
    });
    let removing = validated.value().get("no") == Some(&Value::Bool(true));
    if present == removing {
        return Err(DomainError::InvalidResponse);
    }
    Ok(result)
}

fn plan_forward(router: &RouterCtx, rule: &PortForward, remove: bool) -> Result<ChangeOp> {
    let mut body = json!({"interface":rule.interface});
    let fields = body.as_object_mut().ok_or(DomainError::InvalidResponse)?;
    if let Some(protocol) = rule.protocol {
        insert(fields, "protocol", json!(protocol.name()));
    }
    if let Some(port) = rule.port {
        insert(fields, "port", json!(port));
    }
    if let Some(port) = rule.end_port {
        insert(fields, "end-port", json!(port));
    }
    match &rule.target {
        ForwardTarget::Address(address) => insert(fields, "to-address", json!(address)),
        ForwardTarget::Host(host) => insert(fields, "to-host", json!(host)),
    }
    if let Some(port) = rule.to_port {
        insert(fields, "to-port", json!(port));
    }
    if remove {
        insert(fields, "no", json!(true));
    }
    plan(router, "ip static", &body)
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
    let mut words = vec![request.path.clone()];
    for field in ["protocol", "interface", "port"] {
        push(value, field, &mut words);
    }
    if let Some(end) = value.get("end-port") {
        words.push("through".to_owned());
        words.push(end.to_string());
    }
    for field in ["to-address", "to-host", "to-port"] {
        push(value, field, &mut words);
    }
    let line = words.join(" ");
    if value.get("no") == Some(&Value::Bool(true)) {
        format!("no {line}")
    } else {
        line
    }
}

fn push(value: &Value, field: &str, words: &mut Vec<String>) {
    if let Some(item) = value.get(field) {
        words.push(
            item.as_str()
                .map_or_else(|| item.to_string(), ToOwned::to_owned),
        );
    }
}

fn insert(fields: &mut Map<String, Value>, name: &str, value: Value) {
    drop(fields.insert(name.to_owned(), value));
}
