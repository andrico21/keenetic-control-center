//! Catalog-validated NAT mutations with fresh configuration verification.

use alloc::{format, vec};

use kcc_app::workflow::{
    ChangeSet, CliChangeRequest, CliChangeResult, CliCommand as ValidatedCli, WorkflowError,
};
use kcc_catalog::{Risk, ValidatedRequest};
use serde_json::{Map, Value, json};

use super::{
    model::{ForwardTarget, PortForward},
    read,
};
use crate::{
    ChangeOp, DomainError, Result, RouterCtx,
    planning::plan_one,
    request_words::{field_word, negated},
    verification,
};

/// Plans adding one static forwarding rule.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_add_forward(router: &RouterCtx, rule: &PortForward) -> Result<ChangeOp> {
    plan_forward(router, rule, false)
}

/// Plans removing exactly one static forwarding rule.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_remove_forward(router: &RouterCtx, rule: &PortForward) -> Result<ChangeOp> {
    plan_forward(router, rule, true)
}

/// Plans enabling NAT on one interface.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_add_interface(router: &RouterCtx, interface: &str) -> Result<ChangeOp> {
    plan_one(
        router,
        "ip nat",
        &json!({"interface":interface}),
        Risk::Write,
    )
}

/// Plans disabling NAT on one interface.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_remove_interface(router: &RouterCtx, interface: &str) -> Result<ChangeOp> {
    plan_one(
        router,
        "ip nat",
        &json!({"interface":interface,"no":true}),
        Risk::Write,
    )
}

/// Applies a NAT plan and verifies the exact command against a fresh `show rc` read.
///
/// # Errors
///
/// Returns an error when the change workflow fails: dispatch, read-back or audit
/// ([`DomainError::Workflow`]), when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]), or when the read-back does not show the change
/// ([`WorkflowError::VerificationFailed`]).
// NOT cancel-safe: cancelled after the CLI request is sent, the router stays changed
// and the read-back verification never runs.
#[inline]
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
        return Err(WorkflowError::VerificationFailed {
            field: format!("/{}", validated.path.replace(' ', "/")),
        }
        .into());
    }
    Ok(result)
}

/// Plans adding or removing one static forwarding rule.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] when the catalog refuses the request.
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
    plan_one(router, "ip static", &body, Risk::Write)
}

/// The CLI line of one validated NAT request.
fn render(request: &ValidatedRequest) -> String {
    let value = request.value();
    let mut words = vec![request.path.clone()];
    for field in ["protocol", "interface", "port"] {
        words.extend(field_word(value, field));
    }
    if let Some(end) = value.get("end-port") {
        words.push("through".to_owned());
        words.push(end.to_string());
    }
    for field in ["to-address", "to-host", "to-port"] {
        words.extend(field_word(value, field));
    }
    negated(value, words.join(" "))
}

/// Inserts `value` as the member `name` of `fields`.
fn insert(fields: &mut Map<String, Value>, name: &str, value: Value) {
    drop(fields.insert(name.to_owned(), value));
}
