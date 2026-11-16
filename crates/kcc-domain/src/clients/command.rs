//! Catalog validation, CLI rendering, and read-back for client mutations.

use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli, VerificationSpec, WorkflowError},
};
use kcc_catalog::{HttpMethod, Risk, ValidatedRequest};
use serde_json::{Value, json};

use super::read_clients;
use crate::{ChangeOp, DomainError, Result, RouterCtx, cli_token, verification};

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
    let mut operation = ChangeOp::new(
        Vec::new(),
        Vec::new(),
        Risk::Write,
        Permission::Write,
        false,
    );
    for request in requests {
        operation.push(ValidatedCli::new(cli_line(&request)?, request)?);
    }
    Ok(operation)
}

/// Converts planned client commands to a protected CLI request.
pub(super) fn request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    verification::complete(CliChangeRequest::new(
        operation.commands.clone(),
        policy_specs(operation)?,
        operation.permission,
        json!({"operation":"clients"}),
    ))
}

/// Verifies non-host policy commands before the workflow records success.
fn policy_specs(operation: &ChangeOp) -> Result<Vec<VerificationSpec>> {
    operation
        .requests
        .iter()
        .filter(|request| {
            matches!(
                request.path.as_str(),
                "ip hotspot default-policy" | "ip hotspot policy"
            )
        })
        .map(|request| {
            let selection = request
                .value()
                .get("access")
                .or_else(|| request.value().get("policy"))
                .cloned()
                .ok_or(DomainError::InvalidResponse)?;
            let field = if request.path == "ip hotspot default-policy" {
                "/default-policy".to_owned()
            } else {
                let interface = request
                    .value()
                    .get("interface")
                    .and_then(Value::as_str)
                    .ok_or(DomainError::InvalidResponse)?;
                format!(
                    "/policy/{}",
                    interface.replace('~', "~0").replace('/', "~1")
                )
            };
            Ok(VerificationSpec::new(
                vec![
                    "show".to_owned(),
                    "rc".to_owned(),
                    "ip".to_owned(),
                    "hotspot".to_owned(),
                ],
                field,
                selection,
            ))
        })
        .collect()
}

/// Verifies host-affecting commands against the authoritative hotspot read.
pub(super) async fn verify(
    router: &RouterCtx,
    operation: &ChangeOp,
) -> CoreResult<(), WorkflowError> {
    let clients = read_clients(router).await.map_err(WorkflowError::from)?;
    for request in &operation.requests {
        let Some(mac) = request.value().get("mac").and_then(Value::as_str) else {
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
            .value()
            .get(key)
            .and_then(Value::as_str)
            .ok_or(DomainError::InvalidResponse)
    };
    match request.path.as_str() {
        "known host" if request.value().get("no") == Some(&Value::Bool(true)) => {
            Ok(format!("no known host {}", text("mac")?))
        }
        "known host" => Ok(format!(
            "known host {} {}",
            registration_word(text("name")?)?,
            text("mac")?
        )),
        "ip hotspot host" if request.value().get("access").is_some() => Ok(format!(
            "ip hotspot host {} {}",
            text("mac")?,
            text("access")?
        )),
        "ip hotspot host" if request.value().get("schedule").is_some() => Ok(format!(
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
        "ip hotspot default-policy" if request.value().get("access").is_some() => {
            Ok(format!("ip hotspot default-policy {}", text("access")?))
        }
        "ip hotspot default-policy" => Ok(format!("ip hotspot default-policy {}", text("policy")?)),
        "ip hotspot policy" if request.value().get("access").is_some() => Ok(format!(
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

/// A registration name as one quoted CLI word; an empty name is refused.
fn registration_word(name: &str) -> Result<String> {
    if name.is_empty() {
        return Err(DomainError::InvalidCliToken);
    }
    cli_token::quoted(name)
}

/// Compares one requested host mutation with its projected hotspot row.
fn matches_request(request: &ValidatedRequest, client: Option<&super::Client>) -> bool {
    match request.path.as_str() {
        "known host" if request.value().get("no") == Some(&Value::Bool(true)) => client.is_none(),
        "known host" => client.is_some_and(|row| {
            row.registered == Some(true)
                && row.name.as_deref() == request.value().get("name").and_then(Value::as_str)
        }),
        "ip hotspot host" if request.value().get("access").is_some() => client.is_some_and(|row| {
            row.access.as_deref() == request.value().get("access").and_then(Value::as_str)
        }),
        "ip hotspot host" if request.value().get("schedule").is_some() => {
            client.is_some_and(|row| {
                row.schedule.as_deref() == request.value().get("schedule").and_then(Value::as_str)
            })
        }
        "ip hotspot host" => client.is_some_and(|row| {
            row.policy.as_deref() == request.value().get("policy").and_then(Value::as_str)
        }),
        "ip hotspot host priority" => client.is_some_and(|row| {
            row.priority.map(|value| value.to_string())
                == request
                    .value()
                    .get("priority")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
        }),
        "ip hotspot default-policy" | "ip hotspot policy" | "ip hotspot wake" => true,
        _ => false,
    }
}
