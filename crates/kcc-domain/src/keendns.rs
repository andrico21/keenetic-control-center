//! KeenDNS naming, remote web proxies, and cloud control exposure.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "domain planning and asynchronous reads are not useful inline candidates"
)]

use alloc::{collections::BTreeMap, vec};

use crate::descriptor::operation;

mod verification;

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli},
};
use kcc_catalog::{HttpMethod, RawAuthorization, Risk, ValidatedRequest, ValidationIssue};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    cli_token::validate as validate_token, read_show,
};

/// Tolerant `show ndns` state.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct KeenDnsState {
    /// Registered full name.
    pub name: Option<String>,
    /// Registration status.
    pub status: Option<String>,
    /// Whether a name is booked.
    pub booked: Option<bool>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Remote-access security level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteSecurityLevel {
    /// Public exposure.
    Public,
    /// Private-network exposure.
    Private,
}

impl RemoteSecurityLevel {
    /// Stable CLI word.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }
}

/// KeenDNS read inventory.
const READS: &[OperationDescriptor] = &[operation(
    "status",
    "show ndns",
    Risk::Read,
    Permission::Read,
)];

/// KeenDNS and remote-access write inventory.
const WRITES: &[OperationDescriptor] = &[
    operation(
        "book_name",
        "ndns book-name",
        Risk::Write,
        Permission::Write,
    ),
    operation(
        "drop_name",
        "ndns drop-name",
        Risk::Write,
        Permission::Write,
    ),
    operation(
        "proxy",
        "ip http proxy",
        Risk::Management,
        Permission::Write,
    ),
    operation(
        "proxy_upstream",
        "ip http proxy upstream",
        Risk::Management,
        Permission::Write,
    ),
    operation(
        "cloud_security_level",
        "cloud control2 security-level",
        Risk::Management,
        Permission::Write,
    ),
];

/// KeenDNS domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::KeenDns,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &["cloudcontrol"],
};

/// Reads KeenDNS registration state.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_status(router: &RouterCtx) -> Result<KeenDnsState> {
    read_show(&router.client, &["show", "ndns"]).await
}

/// Plans booking a KeenDNS label and domain.
pub fn plan_book_name(router: &RouterCtx, name: &str, domain: &str) -> Result<ChangeOp> {
    validate_token(name)?;
    validate_token(domain)?;
    plan(
        router,
        "ndns book-name",
        &json!({"name":name,"domain":domain}),
        Risk::Write,
    )
}

/// Plans dropping a KeenDNS label and domain.
pub fn plan_drop_name(router: &RouterCtx, name: &str, domain: &str) -> Result<ChangeOp> {
    validate_token(name)?;
    validate_token(domain)?;
    plan(
        router,
        "ndns drop-name",
        &json!({"name":name,"domain":domain}),
        Risk::Write,
    )
}

/// Plans creation or deletion of one named HTTP proxy entry.
pub fn plan_proxy(router: &RouterCtx, name: &str, enabled: bool) -> Result<ChangeOp> {
    validate_token(name)?;
    let body = if enabled {
        json!({"name":name})
    } else {
        json!({"name":name,"no":true})
    };
    plan(router, "ip http proxy", &body, Risk::Management)
}

/// Plans a proxy upstream to one LAN host, given by its IP address, MAC address or host
/// name, on a port from 1 to 65535.
///
/// The upstream line itself is what the catalog validates: its protocol keyword, host
/// and port are checked against the command's documented forms.
pub fn plan_proxy_upstream(
    router: &RouterCtx,
    proxy: &str,
    protocol: &str,
    host: &str,
    port: u16,
) -> Result<ChangeOp> {
    for token in [proxy, protocol, host] {
        validate_token(token)?;
    }
    if port == 0 {
        return Err(DomainError::Validation {
            issues: vec![ValidationIssue::InvalidValue {
                field: "port".to_owned(),
            }],
        });
    }
    let context = validate(router, "ip http proxy", &json!({"name":proxy}))?;
    let line = format!("ip http proxy {proxy} upstream {protocol} {host} {port}");
    let upstream = router
        .catalog
        .validate_cli(&line, RawAuthorization::default())
        .map_err(|issues| DomainError::Validation { issues })?;
    if upstream.path != "ip http proxy upstream" {
        return Err(DomainError::InvalidCliToken);
    }
    let mut operation = ChangeOp::new(
        Vec::new(),
        Vec::new(),
        Risk::Management,
        Permission::Write,
        false,
    );
    operation.push(ValidatedCli::new(format!("ip http proxy {proxy}"), context));
    operation.push(ValidatedCli::new(line, upstream));
    operation.verify = vec![verification::upstream(
        proxy,
        json!({"protocol":protocol,"host":host,"port":port}),
    )];
    Ok(operation)
}

/// Plans cloud-control exposure.
pub fn plan_cloud_security_level(
    router: &RouterCtx,
    level: RemoteSecurityLevel,
) -> Result<ChangeOp> {
    plan(
        router,
        "cloud control2 security-level",
        &json!({"level":level.name()}),
        Risk::Management,
    )
}

/// Converts a KeenDNS plan into a protected workflow request.
pub fn change_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    if !operation.commands.is_empty() {
        return Ok(CliChangeRequest::new(
            operation.commands.clone(),
            operation.verify.clone(),
            operation.permission,
            json!({"operation":"keendns"}),
        ));
    }
    let mut commands = Vec::new();
    for request in &operation.requests {
        let value = request.value();
        let text = |key| {
            value
                .get(key)
                .and_then(Value::as_str)
                .ok_or(DomainError::InvalidResponse)
        };
        let line = match request.path.as_str() {
            "ndns book-name" | "ndns drop-name" => {
                format!("{} {} {}", request.path, text("name")?, text("domain")?)
            }
            "ip http proxy" => {
                let prefix = if value.get("no").and_then(Value::as_bool) == Some(true) {
                    "no "
                } else {
                    ""
                };
                format!("{prefix}ip http proxy {}", text("name")?)
            }
            "cloud control2 security-level" => {
                format!("cloud control2 security-level {}", text("level")?)
            }
            _ => return Err(DomainError::InvalidResponse),
        };
        commands.push(ValidatedCli::new(line, request.clone()));
    }
    Ok(CliChangeRequest::new(
        commands,
        verification::specs(operation)?,
        operation.permission,
        json!({"operation":"keendns"}),
    ))
}

/// Plans one catalog-validated operation.
fn plan(router: &RouterCtx, path: &str, body: &Value, risk: Risk) -> Result<ChangeOp> {
    let request = validate(router, path, body)?;
    Ok(ChangeOp::new(
        vec![request],
        Vec::new(),
        risk,
        Permission::Write,
        false,
    ))
}

/// Validates one catalog request.
fn validate(router: &RouterCtx, path: &str, body: &Value) -> Result<ValidatedRequest> {
    router
        .catalog
        .validate(path, HttpMethod::Post, body)
        .map_err(|issues| DomainError::Validation { issues })
}
