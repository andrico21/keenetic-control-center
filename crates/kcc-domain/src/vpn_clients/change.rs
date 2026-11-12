//! Catalog validation and protected workflow conversion for VPN clients.

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli},
};
use kcc_catalog::{HttpMethod, Risk};
use serde_json::{Value, json};

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
    let mut operation = plan_unclassified(router, change)?;
    let lines = operation
        .requests
        .iter()
        .map(|request| {
            request
                .value
                .get("line")
                .and_then(Value::as_str)
                .ok_or(DomainError::InvalidResponse)
        })
        .collect::<Result<Vec<_>>>()?;
    operation.risk = interfaces::management::classify_generated(router, &lines).await?;
    Ok(operation)
}

/// Plans one non-secret mutation before generated-line management classification.
pub(super) fn plan_unclassified(router: &RouterCtx, change: &VpnClientChange) -> Result<ChangeOp> {
    let (path, body, line) = render::input(change);
    let mut validated = router
        .catalog
        .validate(path, HttpMethod::Post, &body)
        .map_err(|issues| DomainError::Validation { issues })?;
    validated.value = json!({"line":line,"arguments":validated.value});
    Ok(ChangeOp::new(
        vec![validated],
        Vec::new(),
        Risk::Write,
        Permission::Write,
        false,
    ))
}

/// Converts a plan to protected CLI workflow input.
pub(super) fn request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let commands = operation
        .requests
        .iter()
        .map(|request| {
            let line = request
                .value
                .get("line")
                .and_then(Value::as_str)
                .ok_or(DomainError::InvalidResponse)?;
            let mut validated = request.clone();
            validated.value = request
                .value
                .get("arguments")
                .cloned()
                .ok_or(DomainError::InvalidResponse)?;
            if validated.has_secrets() {
                ValidatedCli::from_template(validated, line)
                    .map_err(|_error| DomainError::InvalidResponse)
            } else {
                Ok(ValidatedCli::new(line.to_owned(), validated))
            }
        })
        .collect::<Result<Vec<_>>>()?;
    verification::complete(CliChangeRequest::new(
        commands,
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
