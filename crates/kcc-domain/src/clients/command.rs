//! Catalog validation, CLI rendering, and read-back expectations for client mutations.

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli, VerificationSpec},
};
use kcc_catalog::{Risk, ValidatedRequest};
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainError, Result, RouterCtx, cli_token, planning::validate, pointer, verification,
};

/// Catalog-validates ordered client command inputs.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
pub(super) fn plan(router: &RouterCtx, inputs: &[(&str, Value)]) -> Result<ChangeOp> {
    let requests = inputs
        .iter()
        .map(|(path, body)| validate(router, path, body))
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

/// Converts planned client commands to a protected CLI request, whose host changes are read
/// back from `show ip hotspot` before the workflow audits them.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when a host or policy request lacks a field its
/// read-back needs, carries a priority that is not a number from 0 to 255, or has an unrecognised
/// path, or when a command cannot be given a read-back of its own (a secret-bearing command, or a
/// line that is not exactly one configuration row).
pub(super) fn request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let mut request = verification::complete(CliChangeRequest::new(
        operation.commands.clone(),
        policy_specs(operation)?,
        operation.permission,
        json!({"operation":"clients"}),
    ))?;
    request.verify.extend(host_specs(operation)?);
    Ok(request)
}

/// The `show ip hotspot` row each host-affecting request leaves behind, its MAC address in
/// the lower case the router reports.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when a host request lacks a field its row needs,
/// carries a priority that is not a number from 0 to 255, or has a path that is not a host
/// command.
fn host_specs(operation: &ChangeOp) -> Result<Vec<VerificationSpec>> {
    let mut specs = Vec::new();
    for request in &operation.requests {
        let Some(mac) = request.value().get("mac").and_then(Value::as_str) else {
            continue;
        };
        let Some((mut expected, present)) = host_row(request)? else {
            continue;
        };
        if let Some(fields) = expected.as_object_mut() {
            drop(fields.insert("mac".to_owned(), json!(mac.to_ascii_lowercase())));
        }
        specs.push(VerificationSpec::collection(
            ["show", "ip", "hotspot"].map(str::to_owned).to_vec(),
            String::new(),
            expected,
            present,
        ));
    }
    Ok(specs)
}

/// The hotspot fields one host request sets, and whether its row must exist; `None` for a
/// request that leaves no row to read.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
fn host_row(request: &ValidatedRequest) -> Result<Option<(Value, bool)>> {
    let field = |key: &str| {
        request
            .value()
            .get(key)
            .cloned()
            .ok_or(DomainError::InvalidResponse)
    };
    let has = |key: &str| request.value().get(key).is_some();
    Ok(Some(match request.path.as_str() {
        "known host" if request.value().get("no") == Some(&Value::Bool(true)) => (json!({}), false),
        "known host" => (json!({"registered":true,"name":field("name")?}), true),
        "ip hotspot host" if has("access") => (json!({"access":field("access")?}), true),
        "ip hotspot host" if has("schedule") => (json!({"schedule":field("schedule")?}), true),
        "ip hotspot host" => (json!({"policy":field("policy")?}), true),
        "ip hotspot host priority" => {
            let priority = field("priority")?
                .as_str()
                .and_then(|text| text.parse::<u8>().ok())
                .ok_or(DomainError::InvalidResponse)?;
            (json!({"priority":priority}), true)
        }
        "ip hotspot wake" => return Ok(None),
        _ => return Err(DomainError::InvalidResponse),
    }))
}

/// Verifies non-host policy commands before the workflow records success.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
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
                format!("/policy/{}", pointer::escape(interface))
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

/// Renders one validated request without permitting arbitrary CLI input.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
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
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]).
fn registration_word(name: &str) -> Result<String> {
    if name.is_empty() {
        return Err(DomainError::InvalidCliToken);
    }
    cli_token::quoted(name)
}
