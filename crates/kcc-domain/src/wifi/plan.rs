//! Wi-Fi plan validation and protected CLI rendering.

use alloc::vec;

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli, PresencePredicate, VerificationSpec},
};
use kcc_catalog::{HttpMethod, Risk};
use kcc_rci::ObjectName;
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::{ChangeOp, DomainError, Result, RouterCtx, cli_token, verification};

/// Validates one Wi-Fi plan with optional selected-interface read-back.
pub(super) fn plan(
    router: &RouterCtx,
    name: &ObjectName,
    path: &str,
    body: &Value,
    expected: Option<(&str, Value)>,
) -> Result<ChangeOp> {
    plan_with_risk(router, name, path, body, expected, Risk::Write)
}

/// Validates one Wi-Fi plan with an already-classified risk.
pub(super) fn plan_with_risk(
    router: &RouterCtx,
    name: &ObjectName,
    path: &str,
    body: &Value,
    expected: Option<(&str, Value)>,
    risk: Risk,
) -> Result<ChangeOp> {
    let validated = router
        .catalog
        .validate(path, HttpMethod::Post, body)
        .map_err(|issues| DomainError::Validation { issues })?;
    let verify = expected.map_or_else(Vec::new, |(field, value)| {
        let escaped_name = name.as_str().replace('~', "~0").replace('/', "~1");
        vec![VerificationSpec::new(
            vec!["show".to_owned(), "interface".to_owned()],
            format!("/{escaped_name}/{field}"),
            value,
        )]
    });
    Ok(ChangeOp::new(
        vec![validated],
        verify,
        risk,
        Permission::Write,
        false,
    ))
}

/// Validates one secret Wi-Fi argument and verifies only its protected representation.
pub(super) fn plan_secret(
    router: &RouterCtx,
    name: &ObjectName,
    path: &str,
    argument: &str,
    secret: SecretString,
) -> Result<ChangeOp> {
    let validated = router
        .catalog
        .validate_secret(path, argument, secret)
        .map_err(|issues| DomainError::Validation { issues })?;
    let escaped_name = name.as_str().replace('~', "~0").replace('/', "~1");
    Ok(ChangeOp::new(
        vec![validated],
        vec![VerificationSpec::presence(
            vec!["show".to_owned(), "interface".to_owned()],
            format!("/{escaped_name}/authentication/wpa-psk/ns3"),
            PresencePredicate::MarkerOrLengthRange {
                minimum: 24,
                maximum: 256,
            },
        )],
        Risk::Write,
        Permission::Write,
        false,
    ))
}

/// Converts a Wi-Fi plan into a protected parser request.
pub(super) fn change_request(name: &ObjectName, operation: &ChangeOp) -> Result<CliChangeRequest> {
    let validated = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    if validated.path == "interface authentication wpa-psk" {
        let command = ValidatedCli::from_template(
            validated.clone(),
            &format!("interface {name} authentication wpa-psk {{/psk}}"),
        )
        .map_err(|_error| DomainError::InvalidResponse)?;
        return Ok(CliChangeRequest::new(
            vec![command],
            operation.verify.clone(),
            operation.permission,
            json!({"operation": validated.path, "interface": name.as_str()}),
        ));
    }
    let line = render_line(name, &validated.path, validated.value())?;
    verification::complete(CliChangeRequest::new(
        vec![ValidatedCli::new(line, validated.clone())?],
        operation.verify.clone(),
        operation.permission,
        json!({"operation": validated.path, "interface": name.as_str()}),
    ))
}

/// Renders the closed non-secret Wi-Fi command set.
fn render_line(name: &ObjectName, path: &str, value: &Value) -> Result<String> {
    let negative = value.get("no") == Some(&Value::Bool(true));
    let suffix = match path {
        "interface ssid" => format!("ssid {}", quoted(value, "ssid")?),
        "interface encryption enable" => "encryption enable".to_owned(),
        "interface encryption wpa2" => "encryption wpa2".to_owned(),
        "interface encryption wpa3" => "encryption wpa3".to_owned(),
        "interface hide-ssid" => "hide-ssid".to_owned(),
        "interface up" => "up".to_owned(),
        "interface down" => "down".to_owned(),
        "interface schedule" => format!("schedule {}", string(value, "schedule")?),
        "interface channel" => format!("channel {}", string(value, "channel")?),
        "interface channel width" => format!("channel width {}", string(value, "width")?),
        "interface power" => format!("power {}", integer(value, "power")?),
        "interface country-code" => format!("country-code {}", quoted(value, "code")?),
        "interface band-steering" => "band-steering".to_owned(),
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(if negative {
        format!("no interface {name} {suffix}")
    } else {
        format!("interface {name} {suffix}")
    })
}

/// Extracts a string field.
fn string<'value>(value: &'value Value, field: &str) -> Result<&'value str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(DomainError::InvalidResponse)
}

/// Quotes a string field for the CLI parser.
fn quoted(value: &Value, field: &str) -> Result<String> {
    cli_token::quoted(string(value, field)?)
}

/// Extracts an integer field.
fn integer(value: &Value, field: &str) -> Result<i64> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or(DomainError::InvalidResponse)
}
