//! WAN connection inventory and non-secret configuration plans.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "domain operation names follow the plan; async reads and planning helpers are not useful inline candidates"
)]

use alloc::{collections::BTreeMap, vec};
use core::{net::Ipv4Addr, result::Result as CoreResult};

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand, PresencePredicate, VerificationSpec},
};
use kcc_catalog::{HttpMethod, Risk};
use kcc_rci::ObjectName;
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    descriptor,
    interfaces::{self, ManagementVerdict},
    read_show,
};

/// Tolerant, secret-free WAN response models.
pub mod models;
mod render;
mod verification;

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
    write_operation("password", "interface authentication password"),
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
// cancel-safe: a single read request; cancellation changes nothing on the router.
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
// cancel-safe: management classification performs read-only topology requests.
pub async fn plan_create(router: &RouterCtx, name: &ObjectName) -> Result<ChangeOp> {
    plan_named_generated(
        router,
        name,
        "interface",
        &json!({"name": name}),
        Vec::new(),
    )
    .await
}

/// Plans deletion of a named connection interface.
// cancel-safe: management classification performs read-only topology requests.
pub async fn plan_delete(router: &RouterCtx, name: &ObjectName) -> Result<ChangeOp> {
    plan_named_generated(
        router,
        name,
        "interface",
        &json!({"name": name, "no": true}),
        Vec::new(),
    )
    .await
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

/// Plans a PPP authentication password while retaining plaintext only in protected storage.
pub fn plan_password(
    router: &RouterCtx,
    name: &ObjectName,
    password: SecretString,
) -> Result<ChangeOp> {
    let validated = router
        .catalog
        .validate_secret("interface authentication password", "password", password)
        .map_err(|issues| DomainError::Validation { issues })?;
    let escaped_name = name.as_str().replace('~', "~0").replace('/', "~1");
    Ok(ChangeOp::new(
        vec![validated],
        vec![VerificationSpec::presence(
            vec!["show".to_owned(), "interface".to_owned()],
            format!("/{escaped_name}/authentication/password/ns3"),
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
// cancel-safe: management classification performs read-only topology requests.
pub async fn plan_priority(
    router: &RouterCtx,
    name: &ObjectName,
    priority: i64,
) -> Result<ChangeOp> {
    plan_named_generated(
        router,
        name,
        "interface ip global",
        &json!({"priority": priority}),
        Vec::new(),
    )
    .await
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
    render::request(name, operation)
}

/// Builds a read descriptor.
const fn read_operation(name: &'static str, catalog_path: &'static str) -> OperationDescriptor {
    descriptor::operation(name, catalog_path, Risk::Read, Permission::Read)
}

/// Builds a write descriptor.
const fn write_operation(name: &'static str, catalog_path: &'static str) -> OperationDescriptor {
    descriptor::operation(name, catalog_path, Risk::Write, Permission::Write)
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

/// Validates and classifies a generated named-interface operation.
// cancel-safe: management classification performs read-only topology requests.
async fn plan_named_generated(
    router: &RouterCtx,
    name: &ObjectName,
    catalog_path: &str,
    body: &Value,
    verify: Vec<VerificationSpec>,
) -> Result<ChangeOp> {
    let operation = plan_with_risk(router, catalog_path, body, verify, Risk::Write)?;
    let request = render::request(name, &operation)?;
    let lines = request
        .commands
        .iter()
        .map(CliCommand::expose_for_send)
        .collect::<CoreResult<Vec<_>, _>>()
        .map_err(|_error| DomainError::InvalidResponse)?;
    let rendered = lines.iter().map(|line| line.as_str()).collect::<Vec<_>>();
    let risk = interfaces::management::classify_generated(router, &rendered).await?;
    Ok(ChangeOp { risk, ..operation })
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
