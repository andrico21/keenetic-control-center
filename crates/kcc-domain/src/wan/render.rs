//! Protected WAN parser request construction.

use kcc_app::workflow::{CliChangeRequest, CliCommand as ValidatedCli};
use kcc_rci::ObjectName;
use serde_json::{Value, json};

use super::verification;
use crate::{ChangeOp, DomainError, Result, cli_token};

/// Converts a named WAN plan into a verified parser request.
pub(super) fn request(name: &ObjectName, operation: &ChangeOp) -> Result<CliChangeRequest> {
    let validated = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let value = validated.value();
    if validated.path == "interface authentication password" {
        let command = ValidatedCli::from_template(
            validated.clone(),
            &format!("interface {name} authentication password {{/password}}"),
        )
        .map_err(|_error| DomainError::InvalidResponse)?;
        return Ok(CliChangeRequest::new(
            vec![command],
            operation.verify.clone(),
            operation.permission,
            json!({"operation":validated.path,"interface":name.as_str()}),
        ));
    }
    let line = match validated.path.as_str() {
        "interface" if value.get("no") == Some(&Value::Bool(true)) => {
            format!("no interface {name}")
        }
        "interface" => format!("interface {name}"),
        "interface ip address dhcp" => format!("interface {name} ip address dhcp"),
        "interface ip address" => format!(
            "interface {name} ip address {} {}",
            string_field(value, "address")?,
            string_field(value, "mask")?
        ),
        "interface authentication identity" => format!(
            "interface {name} authentication identity {}",
            quoted_field(value, "identity")?
        ),
        "interface connect" => format!(
            "interface {name} connect via {}",
            string_field(value, "via")?
        ),
        "interface ip global" => format!(
            "interface {name} ip global {}",
            integer_field(value, "priority")?
        ),
        "interface ip mtu" => format!("interface {name} ip mtu {}", integer_field(value, "mtu")?),
        "interface ipcp default-route" if value.get("no") == Some(&Value::Bool(true)) => {
            format!("no interface {name} ipcp default-route")
        }
        "interface ipcp default-route" => format!("interface {name} ipcp default-route"),
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(CliChangeRequest::new(
        vec![ValidatedCli::new(line, validated.clone())?],
        verification::specs(name, validated)?,
        operation.permission,
        json!({"operation":validated.path,"interface":name.as_str()}),
    ))
}

/// Extracts a string request field.
fn string_field<'value>(value: &'value Value, field: &str) -> Result<&'value str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(DomainError::InvalidResponse)
}

/// Quotes one string request field for the CLI parser.
fn quoted_field(value: &Value, field: &str) -> Result<String> {
    cli_token::quoted(string_field(value, field)?)
}

/// Extracts an integer request field.
fn integer_field(value: &Value, field: &str) -> Result<i64> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or(DomainError::InvalidResponse)
}
