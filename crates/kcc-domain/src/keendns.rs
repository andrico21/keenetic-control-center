//! KeenDNS naming, remote web proxies, and cloud control exposure.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "domain planning and asynchronous reads are not useful inline candidates"
)]

use alloc::{collections::BTreeMap, vec};

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand},
};
use kcc_catalog::{HttpMethod, Risk, ValidatedRequest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    read_show,
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

/// Plans a proxy upstream to one LAN host.
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
    let context = validate(router, "ip http proxy", &json!({"name":proxy}))?;
    let mut upstream = validate(router, "ip http proxy upstream", &json!({}))?;
    upstream.value = json!({"protocol":protocol,"host":host,"port":port});
    Ok(ChangeOp::new(
        vec![context, upstream],
        Vec::new(),
        Risk::Management,
        Permission::Write,
        false,
    ))
}

/// Plans cloud-control exposure.
pub fn plan_cloud_security_level(
    router: &RouterCtx,
    level: RemoteSecurityLevel,
) -> Result<ChangeOp> {
    let mut request = validate(router, "cloud control2 security-level", &json!({}))?;
    request.value = json!({"level":level.name()});
    Ok(ChangeOp::new(
        vec![request],
        Vec::new(),
        Risk::Management,
        Permission::Write,
        false,
    ))
}

/// Converts a KeenDNS plan into a protected workflow request.
pub fn change_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let mut commands = Vec::new();
    let mut proxy_name = None;
    for request in &operation.requests {
        let line = match request.path.as_str() {
            "ndns book-name" | "ndns drop-name" => format!(
                "{} {} {}",
                request.path,
                request
                    .value
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or(DomainError::InvalidResponse)?,
                request
                    .value
                    .get("domain")
                    .and_then(Value::as_str)
                    .ok_or(DomainError::InvalidResponse)?
            ),
            "ip http proxy" => {
                let name = request
                    .value
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or(DomainError::InvalidResponse)?;
                proxy_name = Some(name.to_owned());
                let prefix = if request.value.get("no").and_then(Value::as_bool) == Some(true) {
                    "no "
                } else {
                    ""
                };
                format!("{prefix}ip http proxy {name}")
            }
            "ip http proxy upstream" => format!(
                "ip http proxy {} upstream {} {} {}",
                proxy_name.as_deref().ok_or(DomainError::InvalidResponse)?,
                request
                    .value
                    .get("protocol")
                    .and_then(Value::as_str)
                    .ok_or(DomainError::InvalidResponse)?,
                request
                    .value
                    .get("host")
                    .and_then(Value::as_str)
                    .ok_or(DomainError::InvalidResponse)?,
                request
                    .value
                    .get("port")
                    .and_then(Value::as_u64)
                    .ok_or(DomainError::InvalidResponse)?
            ),
            "cloud control2 security-level" => format!(
                "cloud control2 security-level {}",
                request
                    .value
                    .get("level")
                    .and_then(Value::as_str)
                    .ok_or(DomainError::InvalidResponse)?
            ),
            _ => return Err(DomainError::InvalidResponse),
        };
        commands.push(CliCommand::new(line, request.clone()));
    }
    Ok(CliChangeRequest::new(
        commands,
        Vec::new(),
        operation.permission,
        json!({"operation":"keendns"}),
    ))
}

/// Builds one operation descriptor.
const fn operation(
    name: &'static str,
    catalog_path: &'static str,
    risk: Risk,
    permission: Permission,
) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk,
        permission,
        persists_immediately: false,
    }
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

/// Rejects values that cannot be represented as one unquoted router CLI token.
fn validate_token(value: &str) -> Result<()> {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || value.contains(['\'', '"', '\\', ';', '|'])
    {
        return Err(DomainError::InvalidCliToken);
    }
    Ok(())
}
