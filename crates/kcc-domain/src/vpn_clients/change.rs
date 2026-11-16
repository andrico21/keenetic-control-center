//! Catalog validation and protected workflow conversion for VPN clients.

use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli},
};
use kcc_catalog::{HttpMethod, Risk};
use serde_json::json;

use super::{VpnClientChange, render};
use crate::{
    ChangeOp, DomainError, OperationDescriptor, Result, RouterCtx, interfaces, verification,
};

/// Catalog-filtered VPN client write inventory.
pub(super) const WRITES: &[OperationDescriptor] = &[
    operation("create", "interface"),
    operation("delete", "interface"),
    operation("enabled", "interface up"),
    operation("wireguard_generate_key", "interface wireguard private-key"),
    operation("wireguard_import", "interface wireguard private-key"),
    operation(
        "wireguard_peer_psk",
        "interface wireguard peer preshared-key",
    ),
    operation("wireguard_listen_port", "interface wireguard listen-port"),
    operation("wireguard_peer", "interface wireguard peer"),
    operation("wireguard_endpoint", "interface wireguard peer endpoint"),
    operation("wireguard_allowed_ip", "interface wireguard peer allow-ips"),
    operation(
        "wireguard_keepalive",
        "interface wireguard peer keepalive-interval",
    ),
    operation("wireguard_asc", "interface wireguard asc"),
    operation("zerotier_network", "interface zerotier network-id"),
    operation("zerotier_routes", "interface zerotier accept-routes"),
    operation("openvpn_routes", "interface openvpn accept-routes"),
    operation("openconnect_protocol", "interface openconnect protocol"),
    operation("proxy_protocol", "interface proxy protocol"),
    operation("proxy_upstream", "interface proxy upstream"),
    operation("ike_policy", "crypto ike policy"),
    operation("ike_proposal", "crypto ike proposal"),
    operation("ipsec_profile", "crypto ipsec profile"),
    operation("ipsec_transform", "crypto ipsec transform-set"),
    operation("crypto_map", "crypto map"),
    operation("ppp_password", "interface authentication password"),
    operation("ipsec_psk", "interface ipsec preshared-key"),
    operation("ike_psk", "crypto ike key"),
    operation("profile_psk", "crypto ipsec profile preshared-key"),
    operation("profile_xauth", "crypto ipsec profile xauth-password"),
];

/// Plans one non-secret mutation.
// cancel-safe: management classification performs read-only topology requests.
pub(super) async fn plan(router: &RouterCtx, change: &VpnClientChange) -> Result<ChangeOp> {
    classify(router, unclassified(router, change)?).await
}

/// Classifies every generated command in one complete VPN client operation.
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
    operation.risk = interfaces::management::classify_generated(router, &rendered).await?;
    Ok(operation)
}

/// Appends one catalog-validated non-secret mutation to an aggregate operation.
pub(super) fn append(
    router: &RouterCtx,
    operation: &mut ChangeOp,
    change: &VpnClientChange,
) -> Result<()> {
    operation.push(command(router, change)?);
    Ok(())
}

/// Plans one non-secret mutation before complete-operation classification.
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
fn command(router: &RouterCtx, change: &VpnClientChange) -> Result<ValidatedCli> {
    let (path, body, line) = render::input(change);
    let validated = router
        .catalog
        .validate(path, HttpMethod::Post, &body)
        .map_err(|issues| DomainError::Validation { issues })?;
    Ok(ValidatedCli::new(line, validated))
}

/// Converts a plan to protected CLI workflow input.
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

/// Builds an ordinary write descriptor.
const fn operation(name: &'static str, catalog_path: &'static str) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk: Risk::Write,
        permission: Permission::Write,
        persists_immediately: false,
    }
}
