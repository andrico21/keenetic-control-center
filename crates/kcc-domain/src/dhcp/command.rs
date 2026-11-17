//! Catalog validation and CLI rendering for DHCP mutations.

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli, VerificationSpec},
};
use kcc_catalog::{Risk, ValidatedRequest};
use serde_json::{Value, json};

use crate::{ChangeOp, DomainError, Result, RouterCtx, planning::validate, verification};

/// Catalog-validates ordered DHCP command inputs.
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
    Ok(ChangeOp::new(
        requests,
        Vec::new(),
        Risk::Write,
        Permission::Write,
        false,
    ))
}

/// Converts catalog requests to ordered DHCP CLI commands, verified before the workflow
/// audits them: each line in the running configuration, and each static lease in `show rc`.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
pub(super) fn request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let mut pool_name = None;
    let mut commands = Vec::new();
    let mut leases = Vec::new();
    for validated in &operation.requests {
        match validated.path.as_str() {
            "ip dhcp pool" => pool_name = validated.value().get("name").and_then(Value::as_str),
            "ip dhcp host" => leases.push(VerificationSpec::collection(
                ["show", "rc", "ip", "dhcp", "host"]
                    .map(str::to_owned)
                    .to_vec(),
                String::new(),
                json!({"mac": validated.value().get("host").ok_or(DomainError::InvalidResponse)?}),
                true,
            )),
            _ => {}
        }
        commands.push(ValidatedCli::new(
            cli_line(validated, pool_name)?,
            validated.clone(),
        )?);
    }
    let mut request = verification::complete(CliChangeRequest::new(
        commands,
        Vec::new(),
        operation.permission,
        json!({"operation":"dhcp"}),
    ))?;
    request.verify.extend(leases);
    Ok(request)
}

/// Renders one validated DHCP request.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
fn cli_line(request: &ValidatedRequest, pool_name: Option<&str>) -> Result<String> {
    let text = |key: &str| {
        request
            .value()
            .get(key)
            .and_then(Value::as_str)
            .ok_or(DomainError::InvalidResponse)
    };
    let pool = || pool_name.ok_or(DomainError::InvalidResponse);
    match request.path.as_str() {
        "ip dhcp host" => Ok(format!("ip dhcp host {} {}", text("host")?, text("ip")?)),
        "ip dhcp pool" => Ok(format!("ip dhcp pool {}", text("name")?)),
        "ip dhcp pool range" => Ok(format!(
            "ip dhcp pool {} range {} {}",
            pool()?,
            text("begin")?,
            text("end")?
        )),
        "ip dhcp pool default-router" => Ok(format!(
            "ip dhcp pool {} default-router {}",
            pool()?,
            text("address")?
        )),
        "ip dhcp pool dns-server" if request.value().get("no") == Some(&Value::Bool(true)) => {
            Ok(format!("no ip dhcp pool {} dns-server", pool()?))
        }
        "ip dhcp pool dns-server" if request.value().get("disable") == Some(&Value::Bool(true)) => {
            Ok(format!("ip dhcp pool {} dns-server disable", pool()?))
        }
        "ip dhcp pool dns-server" => Ok(format!(
            "ip dhcp pool {} dns-server {}",
            pool()?,
            text("address1")?
        )),
        "ip dhcp pool lease" => Ok(format!(
            "ip dhcp pool {} lease {}",
            pool()?,
            request
                .value()
                .get("lease")
                .and_then(Value::as_u64)
                .ok_or(DomainError::InvalidResponse)?
        )),
        "ip dhcp pool bind" => Ok(format!(
            "ip dhcp pool {} bind {}",
            pool()?,
            text("interface")?
        )),
        "ip dhcp pool enable" if request.value().get("no") == Some(&Value::Bool(true)) => {
            Ok(format!("no ip dhcp pool {} enable", pool()?))
        }
        "ip dhcp pool enable" => Ok(format!("ip dhcp pool {} enable", pool()?)),
        _ => Err(DomainError::InvalidResponse),
    }
}
