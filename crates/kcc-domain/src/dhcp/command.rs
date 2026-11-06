//! Catalog validation and CLI rendering for DHCP mutations.

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand},
};
use kcc_catalog::{HttpMethod, Risk, ValidatedRequest};
use serde_json::{Value, json};

use crate::{ChangeOp, DomainError, Result, RouterCtx};

/// Catalog-validates ordered DHCP command inputs.
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

/// Converts catalog requests to ordered DHCP CLI commands.
pub(super) fn request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let mut pool_name = None;
    let mut commands = Vec::new();
    for validated in &operation.requests {
        if validated.path == "ip dhcp pool" {
            pool_name = validated.value.get("name").and_then(Value::as_str);
        }
        commands.push(CliCommand::new(
            cli_line(validated, pool_name)?,
            validated.clone(),
        ));
    }
    Ok(CliChangeRequest::new(
        commands,
        Vec::new(),
        operation.permission,
        json!({"operation":"dhcp"}),
    ))
}

/// Renders one validated DHCP request.
fn cli_line(request: &ValidatedRequest, pool_name: Option<&str>) -> Result<String> {
    let text = |key: &str| {
        request
            .value
            .get(key)
            .and_then(Value::as_str)
            .ok_or(DomainError::InvalidResponse)
    };
    let pool = || pool_name.ok_or(DomainError::InvalidResponse);
    match request.path.as_str() {
        "ip dhcp host" => Ok(format!("ip dhcp host {}", text("host")?)),
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
        "ip dhcp pool dns-server" if request.value.get("disable") == Some(&Value::Bool(true)) => {
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
                .value
                .get("lease")
                .and_then(Value::as_u64)
                .ok_or(DomainError::InvalidResponse)?
        )),
        "ip dhcp pool bind" => Ok(format!(
            "ip dhcp pool {} bind {}",
            pool()?,
            text("interface")?
        )),
        "ip dhcp pool enable" if request.value.get("no") == Some(&Value::Bool(true)) => {
            Ok(format!("no ip dhcp pool {} enable", pool()?))
        }
        "ip dhcp pool enable" => Ok(format!("ip dhcp pool {} enable", pool()?)),
        _ => Err(DomainError::InvalidResponse),
    }
}
