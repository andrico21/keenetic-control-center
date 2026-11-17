//! WAN connection inventory and non-secret configuration plans.

use alloc::{collections::BTreeMap, vec};
use core::net::Ipv4Addr;

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, PresencePredicate, VerificationSpec},
};
use kcc_catalog::Risk;
use kcc_rci::ObjectName;
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    descriptor,
    interfaces::{self, ManagementVerdict},
    planning::validate,
    pointer, read_show,
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
const READS: &[OperationDescriptor] = &[descriptor::read("connections", "show interface")];

/// WAN write inventory.
const WRITES: &[OperationDescriptor] = &[
    descriptor::write("create", "interface"),
    descriptor::write("delete", "interface"),
    descriptor::write("address_static", "interface ip address"),
    descriptor::write("address_dhcp", "interface ip address dhcp"),
    descriptor::write("identity", "interface authentication identity"),
    descriptor::write("password", "interface authentication password"),
    descriptor::write("connect_via", "interface connect"),
    descriptor::write("priority", "interface ip global"),
    descriptor::write("mtu", "interface ip mtu"),
    descriptor::write("default_route", "interface ipcp default-route"),
];

/// WAN domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Wan,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Reads IPoE, PPPoE, L2TP, and PPTP connections without returning credentials.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// cancel-safe: a single read request; cancellation changes nothing on the router.
#[inline]
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
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
// cancel-safe: management classification performs read-only topology requests.
#[inline]
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
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
// cancel-safe: management classification performs read-only topology requests.
#[inline]
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
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_dhcp(
    router: &RouterCtx,
    name: &ObjectName,
    verdict: ManagementVerdict,
) -> Result<ChangeOp> {
    plan_with_risk(
        router,
        "interface ip address dhcp",
        &json!({}),
        Vec::new(),
        verdict.risk(name),
    )
}

/// Plans static IPv4 addressing.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_static_address(
    router: &RouterCtx,
    name: &ObjectName,
    address: StaticAddress,
    verdict: ManagementVerdict,
) -> Result<ChangeOp> {
    plan_with_risk(
        router,
        "interface ip address",
        &json!({"address": address.address, "mask": address.mask}),
        Vec::new(),
        verdict.risk(name),
    )
}

/// Plans the public authentication identity without handling a password.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
// cancel-safe: management classification performs read-only topology requests.
#[inline]
pub async fn plan_identity(
    router: &RouterCtx,
    name: &ObjectName,
    identity: &str,
) -> Result<ChangeOp> {
    plan_named_generated(
        router,
        name,
        "interface authentication identity",
        &json!({"identity": identity}),
        Vec::new(),
    )
    .await
}

/// Plans a PPP authentication password while retaining plaintext only in protected storage;
/// its read-back requires the stored value to differ from the one before the write.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
// cancel-safe: management classification performs read-only topology requests.
#[inline]
pub async fn plan_password(
    router: &RouterCtx,
    name: &ObjectName,
    password: SecretString,
) -> Result<ChangeOp> {
    let validated = router
        .catalog
        .validate_secret("interface authentication password", "password", password)
        .map_err(|issues| DomainError::Validation { issues })?;
    let escaped_name = pointer::escape(name.as_str());
    let operation = ChangeOp::new(
        vec![validated],
        vec![
            VerificationSpec::presence(
                vec!["show".to_owned(), "interface".to_owned()],
                format!("/{escaped_name}/authentication/password/ns3"),
                PresencePredicate::MarkerOrLengthRange {
                    minimum: 24,
                    maximum: 256,
                },
            ),
            VerificationSpec::replaced(format!("interface {name} authentication password")),
        ],
        Risk::Write,
        Permission::Write,
        false,
    );
    classified(router, name, operation).await
}

/// Plans the underlying interface used by a tunneled connection.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
// cancel-safe: management classification performs read-only topology requests.
#[inline]
pub async fn plan_connect_via(
    router: &RouterCtx,
    name: &ObjectName,
    via: &ObjectName,
) -> Result<ChangeOp> {
    plan_named_generated(
        router,
        name,
        "interface connect",
        &json!({"via": via}),
        Vec::new(),
    )
    .await
}

/// Plans global-routing priority.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
// cancel-safe: management classification performs read-only topology requests.
#[inline]
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
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
// cancel-safe: management classification performs read-only topology requests.
#[inline]
pub async fn plan_mtu(router: &RouterCtx, name: &ObjectName, mtu: i64) -> Result<ChangeOp> {
    plan_named_generated(
        router,
        name,
        "interface ip mtu",
        &json!({"mtu": mtu}),
        Vec::new(),
    )
    .await
}

/// Plans whether IPCP supplies a default route.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
// cancel-safe: management classification performs read-only topology requests.
#[inline]
pub async fn plan_default_route(
    router: &RouterCtx,
    name: &ObjectName,
    enabled: bool,
) -> Result<ChangeOp> {
    let body = if enabled {
        json!({})
    } else {
        json!({"no": true})
    };
    plan_named_generated(
        router,
        name,
        "interface ipcp default-route",
        &body,
        Vec::new(),
    )
    .await
}

/// Converts a WAN plan into a protected parser request.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when the plan holds no request, the request is not a
/// WAN command, lacks a field, or the password command cannot be bound to its template;
/// [`DomainError::InvalidCliToken`] when an identity cannot be quoted; and
/// [`DomainError::Workflow`] when a rendered line does not match its request.
#[inline]
pub fn change_request(name: &ObjectName, operation: &ChangeOp) -> Result<CliChangeRequest> {
    render::request(name, operation)
}

/// Validates and classifies a generated named-interface operation.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
// cancel-safe: management classification performs read-only topology requests.
async fn plan_named_generated(
    router: &RouterCtx,
    name: &ObjectName,
    catalog_path: &str,
    body: &Value,
    verify: Vec<VerificationSpec>,
) -> Result<ChangeOp> {
    let operation = plan_with_risk(router, catalog_path, body, verify, Risk::Write)?;
    classified(router, name, operation).await
}

/// Raises `operation` to management risk when the connection `name` carries kcc's own
/// connection; every WAN line names only that interface, so it alone is classified.
///
/// # Errors
///
/// Returns [`DomainError::Rci`] when a router request of the management check fails, and
/// [`DomainError::InvalidResponse`] when its replies do not decode.
// cancel-safe: management classification performs read-only topology requests.
async fn classified(
    router: &RouterCtx,
    name: &ObjectName,
    operation: ChangeOp,
) -> Result<ChangeOp> {
    let risk = interfaces::detect_management(router, name)
        .await?
        .risk(name);
    Ok(ChangeOp { risk, ..operation })
}

/// Validates one WAN operation with explicit risk.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
fn plan_with_risk(
    router: &RouterCtx,
    catalog_path: &str,
    body: &Value,
    verify: Vec<VerificationSpec>,
    risk: Risk,
) -> Result<ChangeOp> {
    let validated = validate(router, catalog_path, body)?;
    Ok(ChangeOp::new(
        vec![validated],
        verify,
        risk,
        Permission::Write,
        false,
    ))
}
