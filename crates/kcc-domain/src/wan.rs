//! WAN connection inventory and non-secret configuration plans.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "domain operation names follow the plan; async reads and planning helpers are not useful inline candidates"
)]

use alloc::{collections::BTreeMap, vec};
use core::net::Ipv4Addr;

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli, VerificationSpec},
};
use kcc_catalog::{HttpMethod, Risk};
use kcc_rci::ObjectName;
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    interfaces::ManagementVerdict, read_show,
};

/// Tolerant, secret-free WAN response models.
pub mod models;

/// Tolerant WAN connection view.
pub type Connection = models::Connection;
/// Supported WAN connection kind.
pub type ConnectionKind = models::ConnectionKind;

/// Static IPv4 address configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct StaticAddress {
    /// Interface address.
    pub address: Ipv4Addr,
    /// Contiguous network mask.
    pub mask: Ipv4Addr,
}

impl StaticAddress {
    /// Creates a static address and network-mask pair.
    #[inline]
    #[must_use]
    pub const fn new(address: Ipv4Addr, mask: Ipv4Addr) -> Self {
        Self { address, mask }
    }
}

/// WAN read inventory.
const READS: &[OperationDescriptor] = &[read_operation("connections", "show interface")];

/// WAN write inventory.
const WRITES: &[OperationDescriptor] = &[
    write_operation("create", "interface"),
    write_operation("delete", "interface"),
    write_operation("address_static", "interface ip address"),
    write_operation("address_dhcp", "interface ip address dhcp"),
    write_operation("identity", "interface authentication identity"),
    write_operation("connect_via", "interface connect"),
    write_operation("priority", "interface ip global"),
    write_operation("mtu", "interface ip mtu"),
    write_operation("default_route", "interface ipcp default-route"),
];

/// WAN domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Wan,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Reads IPoE, PPPoE, L2TP, and PPTP connections without returning credentials.
pub async fn read_connections(router: &RouterCtx) -> Result<BTreeMap<String, Connection>> {
    let interfaces: BTreeMap<String, Value> =
        read_show(&router.client, &["show", "interface"]).await?;
    let connections = interfaces
        .into_iter()
        .filter_map(|(name, value)| {
            let connection = serde_json::from_value::<Connection>(value).ok()?;
            connection.kind.map(|_| (name, connection))
        })
        .collect::<BTreeMap<_, _>>();
    Ok(connections)
}

/// Plans creation of a named connection interface.
pub fn plan_create(router: &RouterCtx, name: &ObjectName) -> Result<ChangeOp> {
    plan(router, "interface", &json!({"name": name}), Vec::new())
}

/// Plans deletion of a named connection interface.
pub fn plan_delete(router: &RouterCtx, name: &ObjectName) -> Result<ChangeOp> {
    plan(
        router,
        "interface",
        &json!({"name": name, "no": true}),
        Vec::new(),
    )
}

/// Plans DHCP addressing for an IPoE interface.
pub fn plan_dhcp(
    router: &RouterCtx,
    name: &ObjectName,
    verdict: ManagementVerdict,
) -> Result<ChangeOp> {
    plan_named(
        router,
        name,
        "interface ip address dhcp",
        &json!({}),
        Vec::new(),
        verdict.risk(name),
    )
}

/// Plans static IPv4 addressing.
pub fn plan_static_address(
    router: &RouterCtx,
    name: &ObjectName,
    address: StaticAddress,
    verdict: ManagementVerdict,
) -> Result<ChangeOp> {
    plan_named(
        router,
        name,
        "interface ip address",
        &json!({"address": address.address, "mask": address.mask}),
        Vec::new(),
        verdict.risk(name),
    )
}

/// Plans the public authentication identity without handling a password.
pub fn plan_identity(router: &RouterCtx, name: &ObjectName, identity: &str) -> Result<ChangeOp> {
    plan_named(
        router,
        name,
        "interface authentication identity",
        &json!({"identity": identity}),
        Vec::new(),
        Risk::Write,
    )
}

/// Plans the underlying interface used by a tunneled connection.
pub fn plan_connect_via(
    router: &RouterCtx,
    name: &ObjectName,
    via: &ObjectName,
) -> Result<ChangeOp> {
    plan_named(
        router,
        name,
        "interface connect",
        &json!({"via": via}),
        Vec::new(),
        Risk::Write,
    )
}

/// Plans global-routing priority.
pub fn plan_priority(router: &RouterCtx, name: &ObjectName, priority: i64) -> Result<ChangeOp> {
    plan_named(
        router,
        name,
        "interface ip global",
        &json!({"priority": priority}),
        Vec::new(),
        Risk::Write,
    )
}

/// Plans interface MTU.
pub fn plan_mtu(router: &RouterCtx, name: &ObjectName, mtu: i64) -> Result<ChangeOp> {
    plan_named(
        router,
        name,
        "interface ip mtu",
        &json!({"mtu": mtu}),
        Vec::new(),
        Risk::Write,
    )
}

/// Plans whether IPCP supplies a default route.
pub fn plan_default_route(
    router: &RouterCtx,
    name: &ObjectName,
    enabled: bool,
) -> Result<ChangeOp> {
    let body = if enabled {
        json!({})
    } else {
        json!({"no": true})
    };
    plan_named(
        router,
        name,
        "interface ipcp default-route",
        &body,
        Vec::new(),
        Risk::Write,
    )
}

/// Converts a WAN plan into a protected parser request.
pub fn change_request(name: &ObjectName, operation: &ChangeOp) -> Result<CliChangeRequest> {
    let validated = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let value = &validated.value;
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
        "interface connect" => {
            format!(
                "interface {name} connect via {}",
                string_field(value, "via")?
            )
        }
        "interface ip global" => {
            format!(
                "interface {name} ip global {}",
                integer_field(value, "priority")?
            )
        }
        "interface ip mtu" => {
            format!("interface {name} ip mtu {}", integer_field(value, "mtu")?)
        }
        "interface ipcp default-route" if value.get("no") == Some(&Value::Bool(true)) => {
            format!("no interface {name} ipcp default-route")
        }
        "interface ipcp default-route" => format!("interface {name} ipcp default-route"),
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(CliChangeRequest::new(
        vec![ValidatedCli::new(line, validated.clone())],
        operation.verify.clone(),
        operation.permission,
        json!({"operation": validated.path, "interface": name.as_str()}),
    ))
}

/// Builds a read descriptor.
const fn read_operation(name: &'static str, catalog_path: &'static str) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk: Risk::Read,
        permission: Permission::Read,
        persists_immediately: false,
    }
}

/// Builds a write descriptor.
const fn write_operation(name: &'static str, catalog_path: &'static str) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk: Risk::Write,
        permission: Permission::Write,
        persists_immediately: false,
    }
}

/// Validates a named interface operation.
fn plan_named(
    router: &RouterCtx,
    _name: &ObjectName,
    catalog_path: &str,
    body: &Value,
    verify: Vec<VerificationSpec>,
    risk: Risk,
) -> Result<ChangeOp> {
    plan_with_risk(router, catalog_path, body, verify, risk)
}

/// Validates one non-secret WAN operation.
fn plan(
    router: &RouterCtx,
    catalog_path: &str,
    body: &Value,
    verify: Vec<VerificationSpec>,
) -> Result<ChangeOp> {
    plan_with_risk(router, catalog_path, body, verify, Risk::Write)
}

/// Validates one WAN operation with explicit risk.
fn plan_with_risk(
    router: &RouterCtx,
    catalog_path: &str,
    body: &Value,
    verify: Vec<VerificationSpec>,
    risk: Risk,
) -> Result<ChangeOp> {
    let validated = router
        .catalog
        .validate(catalog_path, HttpMethod::Post, body)
        .map_err(|issues| DomainError::Validation { issues })?;
    Ok(ChangeOp::new(
        vec![validated],
        verify,
        risk,
        Permission::Write,
        false,
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
    serde_json::to_string(string_field(value, field)?)
        .map_err(|_error| DomainError::InvalidResponse)
}

/// Extracts an integer request field.
fn integer_field(value: &Value, field: &str) -> Result<i64> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or(DomainError::InvalidResponse)
}
