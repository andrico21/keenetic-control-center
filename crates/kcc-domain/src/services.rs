//! Router services and management listener settings.

use alloc::{collections::BTreeMap, vec};

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli},
};
use kcc_catalog::{Risk, ValidatedRequest};
use kcc_rci::RouterUrl;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    cli_token::validate as validate_token, descriptor, planning::validate,
    request_words::first_argument,
};

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions are not rendered API documentation"
)]
mod tests;
mod verification;

/// Returns the shared service-toggle risk, preserving protection for both toggle directions.
#[inline]
#[must_use]
pub fn service_risk(name: &str) -> Risk {
    if matches!(name, "http" | "ssh" | "telnet") {
        Risk::Management
    } else {
        Risk::Write
    }
}

/// One service returned by `show rc service`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ServiceState {
    /// Catalog service name.
    pub name: Option<String>,
    /// Whether the service is enabled.
    pub enabled: Option<bool>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Service branch beneath the runtime configuration projection.
#[derive(Default, Deserialize)]
#[serde(default)]
struct ServiceProjection {
    /// Configured services.
    service: Vec<ServiceState>,
}

/// Listener kind for management transport settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ManagementListener {
    /// HTTP and HTTPS listener.
    Http,
    /// SSH listener.
    Ssh,
    /// Telnet listener.
    Telnet,
}

impl ManagementListener {
    /// Stable CLI word.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Ssh => "ssh",
            Self::Telnet => "telnet",
        }
    }
}

/// Security level accepted by router management listeners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SecurityLevel {
    /// Reachable from public interfaces.
    Public,
    /// Reachable from private interfaces.
    Private,
    /// Restricted to protected interfaces.
    Protected,
}

impl SecurityLevel {
    /// Stable CLI word.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Protected => "protected",
        }
    }
}

/// HTTP TLS operation supported by the catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HttpSslSetting {
    /// Enables or disables HTTPS.
    Enable(bool),
    /// Changes the HTTPS port.
    Port(u16),
    /// Enables or disables HTTP-to-HTTPS redirection.
    Redirect(bool),
    /// Requests an ACME certificate.
    AcmeGet,
    /// Revokes an ACME certificate.
    AcmeRevoke,
}

/// Service read inventory.
const READS: &[OperationDescriptor] = &[descriptor::operation(
    "list",
    "service http",
    Risk::Read,
    Permission::Read,
)];

/// Service write inventory.
const WRITES: &[OperationDescriptor] = &[
    descriptor::operation(
        "set_service",
        "service http",
        Risk::Write,
        Permission::Write,
    ),
    descriptor::operation(
        "management_port",
        "ip http port",
        Risk::Management,
        Permission::Write,
    ),
    descriptor::operation(
        "management_security_level",
        "ip http security-level",
        Risk::Management,
        Permission::Write,
    ),
    descriptor::operation(
        "http_ssl",
        "ip http ssl enable",
        Risk::Management,
        Permission::Write,
    ),
];

/// Services domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Services,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Reads enabled router services.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]), or when a reply or a plan
/// does not have the expected shape ([`DomainError::InvalidResponse`]).
// cancel-safe: a single read request; cancellation changes nothing on the router.
#[inline]
#[expect(
    clippy::module_name_repetitions,
    reason = "the read is named after the router list it returns, like the reads of the other domain modules"
)]
pub async fn read_services(router: &RouterCtx) -> Result<Vec<ServiceState>> {
    let response = router.client.show_rc(json!({"service":{}})).await?;
    serde_json::from_value::<ServiceProjection>(response.configuration_tree().clone())
        .map(|projection| projection.service)
        .map_err(|_error| DomainError::InvalidResponse)
}

/// Plans enabling or disabling one service present in the selected catalog.
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), or when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_service(router: &RouterCtx, name: &str, enabled: bool) -> Result<ChangeOp> {
    validate_token(name)?;
    let path = format!("service {name}");
    let body = if enabled {
        json!({})
    } else {
        json!({"no":true})
    };
    let request = validate(router, &path, &body)?;
    Ok(ChangeOp::new(
        vec![request],
        Vec::new(),
        service_risk(name),
        Permission::Write,
        false,
    ))
}

/// Plans a management listener port change; moving the plain-HTTP listener the router
/// profile's URL uses is refused, since kcc would lose its own connection mid-change.
///
/// # Errors
///
/// Returns an error when the change would cut kcc off from the router
/// ([`DomainError::ProtectedAccount`]), or when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_port(router: &RouterCtx, listener: ManagementListener, port: u16) -> Result<ChangeOp> {
    let url = router.client.router_url();
    if listener == ManagementListener::Http && !url.is_https() && url.port() != Some(port) {
        return Err(DomainError::ProtectedAccount);
    }
    let path = format!("ip {} port", listener.name());
    let argument = match listener {
        ManagementListener::Http => "port",
        ManagementListener::Ssh | ManagementListener::Telnet => "number",
    };
    plan_management(router, &path, &json!({argument:port}))
}

/// Plans a management listener security-level change.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_security_level(
    router: &RouterCtx,
    listener: ManagementListener,
    level: SecurityLevel,
) -> Result<ChangeOp> {
    let path = format!("ip {} security-level", listener.name());
    plan_management(router, &path, &json!({"level":level.name()}))
}

/// Plans one HTTP TLS or ACME setting; a setting that closes, moves or redirects the
/// listener the router profile's URL uses is refused, since kcc would lose its own
/// connection mid-change.
///
/// # Errors
///
/// Returns an error when the change would cut kcc off from the router
/// ([`DomainError::ProtectedAccount`]), or when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_http_ssl(router: &RouterCtx, setting: HttpSslSetting) -> Result<ChangeOp> {
    if cuts_own_listener(router.client.router_url(), setting) {
        return Err(DomainError::ProtectedAccount);
    }
    let (path, body) = match setting {
        HttpSslSetting::Enable(true) => ("ip http ssl enable", json!({})),
        HttpSslSetting::Enable(false) => ("ip http ssl enable", json!({"no":true})),
        HttpSslSetting::Port(port) => ("ip http ssl port", json!({"port":port})),
        HttpSslSetting::Redirect(true) => ("ip http ssl redirect", json!({})),
        HttpSslSetting::Redirect(false) => ("ip http ssl redirect", json!({"no":true})),
        HttpSslSetting::AcmeGet => ("ip http ssl acme get", json!({})),
        HttpSslSetting::AcmeRevoke => ("ip http ssl acme revoke", json!({})),
    };
    plan_management(router, path, &body)
}

/// Converts a service plan into the only workflow request permitted to execute it.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
#[inline]
pub fn change_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let request = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let line = command_line(request);
    Ok(CliChangeRequest::new(
        vec![ValidatedCli::new(line, request.clone())?],
        verification::specs(request)?,
        operation.permission,
        json!({"operation":request.path}),
    ))
}

/// Whether `setting` closes, moves or redirects the listener `url` reaches the router on.
fn cuts_own_listener(url: &RouterUrl, setting: HttpSslSetting) -> bool {
    let https = url.is_https();
    match setting {
        HttpSslSetting::Enable(enabled) => https && !enabled,
        HttpSslSetting::Port(port) => https && url.port() != Some(port),
        HttpSslSetting::Redirect(redirect) => !https && redirect,
        HttpSslSetting::AcmeGet | HttpSslSetting::AcmeRevoke => false,
    }
}

/// Plans a management-risk operation.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
fn plan_management(router: &RouterCtx, path: &str, body: &Value) -> Result<ChangeOp> {
    let request = validate(router, path, body)?;
    Ok(management_change(request))
}

/// Constructs the shared management-risk operation shape.
fn management_change(request: ValidatedRequest) -> ChangeOp {
    ChangeOp::new(
        vec![request],
        Vec::new(),
        Risk::Management,
        Permission::Write,
        false,
    )
}

/// Serializes a validated fixed-form request into router CLI syntax.
fn command_line(request: &ValidatedRequest) -> String {
    let prefix = if request.value().get("no").and_then(Value::as_bool) == Some(true) {
        "no "
    } else {
        ""
    };
    let argument = first_argument(request.value()).map_or_default(|value| match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => String::new(),
    });
    let separator = if argument.is_empty() { "" } else { " " };
    format!("{prefix}{}{separator}{argument}", request.path)
}
