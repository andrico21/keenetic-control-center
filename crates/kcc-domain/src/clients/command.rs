//! Catalog validation, CLI rendering, and read-back for client mutations.

use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand, WorkflowError},
};
use kcc_catalog::{HttpMethod, Risk, ValidatedRequest};
use serde_json::{Value, json};

use super::read_clients;
use crate::{ChangeOp, DomainError, Result, RouterCtx};

/// Catalog-validates ordered client command inputs.
pub(super) fn plan(router: &RouterCtx, inputs: &[(&str, Value)]) -> Result<ChangeOp> {
    let requests = inputs
        .iter()
        .map(|(path, body)| {
            router
                .catalog
                .validate(path, HttpMethod::Post, body)
                .map_err(|issues| DomainError::Validation { issues })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ChangeOp::new(
        requests,
        Vec::new(),
        Risk::Write,
        Permission::Write,
        false,
    ))
}

/// Converts catalog requests to ordered CLI commands.
pub(super) fn request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let commands = operation
        .requests
        .iter()
        .map(|request| Ok(CliCommand::new(cli_line(request)?, request.clone())))
        .collect::<Result<Vec<_>>>()?;
    Ok(CliChangeRequest::new(
        commands,
        Vec::new(),
        operation.permission,
        json!({"operation":"clients"}),
    ))
}

/// Verifies host-affecting commands against the authoritative hotspot read.
pub(super) async fn verify(
    router: &RouterCtx,
    operation: &ChangeOp,
) -> CoreResult<(), WorkflowError> {
    let clients = read_clients(router).await.map_err(map_domain_error)?;
    for request in &operation.requests {
        let Some(mac) = request.value.get("mac").and_then(Value::as_str) else {
            continue;
        };
        let client = clients.iter().find(|candidate| {
            candidate
                .mac
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case(mac))
        });
        if !matches_request(request, client) {
            return Err(WorkflowError::VerificationFailed {
                field: format!("client/{mac}"),
            });
        }
    }
    Ok(())
}

/// Renders one validated request without permitting arbitrary CLI input.
fn cli_line(request: &ValidatedRequest) -> Result<String> {
    let text = |key: &str| {
        request
            .value
            .get(key)
            .and_then(Value::as_str)
            .ok_or(DomainError::InvalidResponse)
    };
    match request.path.as_str() {
        "known host" if request.value.get("no") == Some(&Value::Bool(true)) => {
            Ok(format!("no known host {}", text("mac")?))
        }
        "known host" => Ok(format!("known host {} {}", text("name")?, text("mac")?)),
        "ip hotspot host" if request.value.get("access").is_some() => Ok(format!(
            "ip hotspot host {} {}",
            text("mac")?,
            text("access")?
        )),
        "ip hotspot host" if request.value.get("schedule").is_some() => Ok(format!(
            "ip hotspot host {} schedule {}",
            text("mac")?,
            text("schedule")?
        )),
        "ip hotspot host" => Ok(format!(
            "ip hotspot host {} policy {}",
            text("mac")?,
            text("policy")?
        )),
        "ip hotspot host priority" => Ok(format!(
            "ip hotspot host {} priority {}",
            text("mac")?,
            text("priority")?
        )),
        "ip hotspot default-policy" if request.value.get("access").is_some() => {
            Ok(format!("ip hotspot default-policy {}", text("access")?))
        }
        "ip hotspot default-policy" => Ok(format!("ip hotspot default-policy {}", text("policy")?)),
        "ip hotspot policy" if request.value.get("access").is_some() => Ok(format!(
            "ip hotspot policy {} {}",
            text("interface")?,
            text("access")?
        )),
        "ip hotspot policy" => Ok(format!(
            "ip hotspot policy {} {}",
            text("interface")?,
            text("policy")?
        )),
        "ip hotspot wake" => Ok(format!("ip hotspot wake {}", text("mac")?)),
        _ => Err(DomainError::InvalidResponse),
    }
}

/// Compares one requested host mutation with its projected hotspot row.
fn matches_request(request: &ValidatedRequest, client: Option<&super::Client>) -> bool {
    match request.path.as_str() {
        "known host" if request.value.get("no") == Some(&Value::Bool(true)) => client.is_none(),
        "known host" => client.is_some_and(|row| {
            row.registered == Some(true)
                && row.name.as_deref() == request.value.get("name").and_then(Value::as_str)
        }),
        "ip hotspot host" if request.value.get("access").is_some() => client.is_some_and(|row| {
            row.access.as_deref() == request.value.get("access").and_then(Value::as_str)
        }),
        "ip hotspot host" if request.value.get("schedule").is_some() => client.is_some_and(|row| {
            row.schedule.as_deref() == request.value.get("schedule").and_then(Value::as_str)
        }),
        "ip hotspot host" => client.is_some_and(|row| {
            row.policy.as_deref() == request.value.get("policy").and_then(Value::as_str)
        }),
        "ip hotspot host priority" => client.is_some_and(|row| {
            row.priority.map(|value| value.to_string())
                == request
                    .value
                    .get("priority")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
        }),
        "ip hotspot default-policy" | "ip hotspot policy" | "ip hotspot wake" => true,
        _ => false,
    }
}

/// Maps domain read failures into workflow execution failures.
fn map_domain_error(error: DomainError) -> WorkflowError {
    match error {
        DomainError::Rci(source) => WorkflowError::Rci(source),
        DomainError::InvalidResponse
        | DomainError::Validation { issues: _ }
        | DomainError::ConfirmationMismatch
        | DomainError::StaticLeaseOutsidePool
        | DomainError::StaticLeaseAddressInUse => WorkflowError::InvalidResponse,
    }
}
