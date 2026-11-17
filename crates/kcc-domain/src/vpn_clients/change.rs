//! Catalog validation and protected workflow conversion for VPN clients.

use alloc::collections::BTreeMap;
use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli},
};
use kcc_catalog::{Risk, ValidationIssue};
use serde_json::{Value, json};

use super::{VpnClientChange, read, render};
use crate::{
    ChangeOp, DomainError, OperationDescriptor, Result, RouterCtx, descriptor, interfaces,
    planning::validate, read_show, verification,
};

/// Catalog-filtered VPN client write inventory.
pub(super) const WRITES: &[OperationDescriptor] = &[
    descriptor::write("create", "interface"),
    descriptor::write("delete", "interface"),
    descriptor::write("enabled", "interface up"),
    descriptor::write("wireguard_generate_key", "interface wireguard private-key"),
    descriptor::write("wireguard_import", "interface wireguard private-key"),
    descriptor::write(
        "wireguard_peer_psk",
        "interface wireguard peer preshared-key",
    ),
    descriptor::write("wireguard_listen_port", "interface wireguard listen-port"),
    descriptor::write("wireguard_peer", "interface wireguard peer"),
    descriptor::write("wireguard_endpoint", "interface wireguard peer endpoint"),
    descriptor::write("wireguard_allowed_ip", "interface wireguard peer allow-ips"),
    descriptor::write(
        "wireguard_keepalive",
        "interface wireguard peer keepalive-interval",
    ),
    descriptor::write("wireguard_asc", "interface wireguard asc"),
    descriptor::write("zerotier_network", "interface zerotier network-id"),
    descriptor::write("zerotier_routes", "interface zerotier accept-routes"),
    descriptor::write("openvpn_routes", "interface openvpn accept-routes"),
    descriptor::write("openconnect_protocol", "interface openconnect protocol"),
    descriptor::write("proxy_protocol", "interface proxy protocol"),
    descriptor::write("proxy_upstream", "interface proxy upstream"),
    descriptor::write("ike_policy", "crypto ike policy"),
    descriptor::write("ike_proposal", "crypto ike proposal"),
    descriptor::write("ipsec_profile", "crypto ipsec profile"),
    descriptor::write("ipsec_transform", "crypto ipsec transform-set"),
    descriptor::write("crypto_map", "crypto map"),
    descriptor::write("ppp_password", "interface authentication password"),
    descriptor::write("ipsec_psk", "interface ipsec preshared-key"),
    descriptor::write("ike_psk", "crypto ike key"),
    descriptor::write("profile_psk", "crypto ipsec profile preshared-key"),
    descriptor::write("profile_xauth", "crypto ipsec profile xauth-password"),
];

/// Plans one non-secret mutation.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] when the catalog refuses the request, or when a deleted
/// name is an existing interface that is not a VPN client; [`DomainError::InvalidCliToken`] when a
/// name or value is not one safe CLI word; [`DomainError::Workflow`] when the rendered line does
/// not match its request; [`DomainError::Rci`] when a router request for the interface list or the
/// management check fails; and [`DomainError::InvalidResponse`] when those replies do not decode
/// or the plan cannot be rendered.
// cancel-safe: management classification performs read-only topology requests.
pub(super) async fn plan(router: &RouterCtx, change: &VpnClientChange) -> Result<ChangeOp> {
    if let VpnClientChange::Delete { name } = change {
        require_vpn_client(router, name).await?;
    }
    classify(router, unclassified(router, change)?).await
}

/// Refuses to remove an existing interface that is not a VPN client; a name the router does
/// not list proceeds and is rejected by the router itself.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]), or when a router request fails or its reply does not
/// decode ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// cancel-safe: a single read request; cancellation changes nothing on the router.
async fn require_vpn_client(router: &RouterCtx, name: &str) -> Result<()> {
    let interfaces: BTreeMap<String, Value> =
        read_show(&router.client, &["show", "interface"]).await?;
    let kind = interfaces
        .get(name)
        .map(|interface| interface.get("type").and_then(Value::as_str));
    match kind {
        None => Ok(()),
        Some(raw) if raw.and_then(read::client_type).is_some() => Ok(()),
        Some(_) => Err(DomainError::Validation {
            issues: vec![ValidationIssue::InvalidValue {
                field: "name".to_owned(),
            }],
        }),
    }
}

/// Classifies every generated command in one complete VPN client operation.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
// cancel-safe: management classification performs read-only topology requests.
pub(super) async fn classify(router: &RouterCtx, mut operation: ChangeOp) -> Result<ChangeOp> {
    let request = request(&operation)?;
    let lines = request
        .commands
        .iter()
        .map(ValidatedCli::expose_for_send)
        .collect::<CoreResult<Vec<_>, _>>()
        .map_err(|_error| DomainError::InvalidResponse)?;
    let rendered = lines.iter().map(|line| line.as_str()).collect::<Vec<_>>();
    let classified = interfaces::management::classify_generated(router, &rendered).await?;
    // A management verdict keeps its recovery bracket; otherwise a destructive request stays
    // destructive.
    operation.risk = if classified == Risk::Write
        && operation
            .requests
            .iter()
            .any(|validated| validated.risk >= Risk::Destructive)
    {
        Risk::Destructive
    } else {
        classified
    };
    Ok(operation)
}

/// Appends one catalog-validated non-secret mutation to an aggregate operation.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] when the catalog refuses the request,
/// [`DomainError::InvalidCliToken`] when a name or value is not one safe CLI word, and
/// [`DomainError::Workflow`] when the rendered line does not match its request.
pub(super) fn append(
    router: &RouterCtx,
    operation: &mut ChangeOp,
    change: &VpnClientChange,
) -> Result<()> {
    operation.push(command(router, change)?);
    Ok(())
}

/// Plans one non-secret mutation before complete-operation classification.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] when the catalog refuses the request,
/// [`DomainError::InvalidCliToken`] when a name or value is not one safe CLI word, and
/// [`DomainError::Workflow`] when the rendered line does not match its request.
fn unclassified(router: &RouterCtx, change: &VpnClientChange) -> Result<ChangeOp> {
    let mut operation = ChangeOp::new(
        Vec::new(),
        Vec::new(),
        Risk::Write,
        Permission::Write,
        false,
    );
    operation.push(command(router, change)?);
    Ok(operation)
}

/// Validates one non-secret mutation and binds its line to the validated request.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
fn command(router: &RouterCtx, change: &VpnClientChange) -> Result<ValidatedCli> {
    let (path, body, line) = render::input(change)?;
    let validated = validate(router, path, &body)?;
    Ok(ValidatedCli::new(line, validated)?)
}

/// Converts a plan to protected CLI workflow input.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
pub(super) fn request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    if operation.commands.is_empty() {
        return Err(DomainError::InvalidResponse);
    }
    verification::complete(CliChangeRequest::new(
        operation.commands.clone(),
        operation.verify.clone(),
        operation.permission,
        json!({"domain":"vpn_clients"}),
    ))
}
