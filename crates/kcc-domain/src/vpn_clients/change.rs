//! VPN client catalog validation, projection decoding, and CLI rendering.
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private conversion helpers directly mirror catalog command names"
    )
)]

use alloc::{format, vec};

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli},
};
use kcc_catalog::{HttpMethod, Risk, ValidatedRequest};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{VpnClientChange, VpnClientStatus, VpnClientType, WireGuardConfig};
use crate::{ChangeOp, DomainError, OperationDescriptor, Result, RouterCtx};

/// Catalog-filtered VPN client write inventory.
pub(super) const WRITES: &[OperationDescriptor] = &[
    operation("create", "interface"),
    operation("delete", "interface"),
    operation("enabled", "interface up"),
    operation("wireguard_generate_key", "interface wireguard private-key"),
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
];

/// Plans one non-secret mutation.
pub(super) fn plan(router: &RouterCtx, change: &VpnClientChange) -> Result<ChangeOp> {
    let (path, body, line) = input(change);
    let mut validated = validate(router, path, &body)?;
    validated.value = json!({"line":line,"arguments":validated.value});
    Ok(ChangeOp::new(
        vec![validated],
        Vec::new(),
        Risk::Write,
        Permission::Write,
        false,
    ))
}

/// Plans all non-secret operations for one imported WireGuard configuration.
pub(super) fn plan_import(
    router: &RouterCtx,
    name: &str,
    config: &WireGuardConfig,
) -> Result<ChangeOp> {
    let mut changes = vec![VpnClientChange::Create {
        name: name.to_owned(),
    }];
    changes.push(VpnClientChange::GenerateWireGuardPrivateKey {
        name: name.to_owned(),
    });
    if let Some(port) = config.interface.listen_port {
        changes.push(VpnClientChange::WireGuardListenPort {
            name: name.to_owned(),
            port,
        });
    }
    for peer in &config.peers {
        changes.push(VpnClientChange::WireGuardPeer {
            name: name.to_owned(),
            public_key: peer.public_key.clone(),
        });
        if let Some(endpoint) = &peer.endpoint {
            let (address, port) = parse_endpoint(endpoint)?;
            changes.push(VpnClientChange::WireGuardEndpoint {
                name: name.to_owned(),
                public_key: peer.public_key.clone(),
                address,
                port,
            });
        }
        for prefix in &peer.allowed_ips {
            let (address, mask) = parse_prefix(prefix)?;
            changes.push(VpnClientChange::WireGuardAllowedIp {
                name: name.to_owned(),
                public_key: peer.public_key.clone(),
                address,
                mask,
            });
        }
        if let Some(seconds) = peer.persistent_keepalive {
            changes.push(VpnClientChange::WireGuardKeepalive {
                name: name.to_owned(),
                public_key: peer.public_key.clone(),
                seconds,
            });
        }
    }
    let mut requests = Vec::new();
    for change in changes {
        requests.extend(plan(router, &change)?.requests);
    }
    Ok(ChangeOp::new(
        requests,
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
            Ok(ValidatedCli::new(line.to_owned(), validated))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(CliChangeRequest::new(
        commands,
        operation.verify.clone(),
        operation.permission,
        json!({"domain":"vpn_clients"}),
    ))
}

/// Decodes supported VPN interfaces while dropping every unknown field.
pub(super) fn decode_clients(value: &Value) -> Vec<VpnClientStatus> {
    let root = value
        .get("show")
        .and_then(|show| show.get("interface"))
        .unwrap_or(value);
    root.as_object()
        .into_iter()
        .flat_map(serde_json::Map::iter)
        .filter_map(|(name, item)| decode_client(name, item))
        .collect()
}

fn decode_client(name: &str, value: &Value) -> Option<VpnClientStatus> {
    let type_name = value.get("type")?.as_str()?;
    let client_type = parse_type(type_name)?;
    let state = value
        .get("state")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some(VpnClientStatus {
        id: value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_owned(),
        client_type,
        state,
        wireguard: decode_for(client_type, VpnClientType::WireGuard, value),
        openvpn: decode_for(client_type, VpnClientType::OpenVpn, value),
        ipsec: decode_for(client_type, VpnClientType::Ipsec, value),
        l2tp_ipsec: decode_for(client_type, VpnClientType::L2tpIpsec, value),
        pptp: decode_for(client_type, VpnClientType::Pptp, value),
        sstp: decode_for(client_type, VpnClientType::Sstp, value),
        zerotier: decode_for(client_type, VpnClientType::ZeroTier, value),
        openconnect: decode_for(client_type, VpnClientType::OpenConnect, value),
        proxy: decode_for(client_type, VpnClientType::Proxy, value),
    })
}

fn decode_for<T>(actual: VpnClientType, expected: VpnClientType, value: &Value) -> Option<T>
where
    T: DeserializeOwned,
{
    (actual == expected)
        .then(|| serde_json::from_value(value.clone()).ok())
        .flatten()
}

fn parse_type(value: &str) -> Option<VpnClientType> {
    match value.to_ascii_lowercase().as_str() {
        "wireguard" => Some(VpnClientType::WireGuard),
        "openvpn" => Some(VpnClientType::OpenVpn),
        "ipsec" => Some(VpnClientType::Ipsec),
        "l2tp" | "l2tp/ipsec" => Some(VpnClientType::L2tpIpsec),
        "pptp" => Some(VpnClientType::Pptp),
        "sstp" => Some(VpnClientType::Sstp),
        "zerotier" => Some(VpnClientType::ZeroTier),
        "openconnect" => Some(VpnClientType::OpenConnect),
        "proxy" => Some(VpnClientType::Proxy),
        _ => None,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one exhaustive match keeps every non-secret VPN operation visibly mapped to its catalog path"
)]
fn input(change: &VpnClientChange) -> (&'static str, Value, String) {
    match change {
        VpnClientChange::Create { name } => (
            "interface",
            json!({"name":name}),
            format!("interface {name}"),
        ),
        VpnClientChange::Delete { name } => (
            "interface",
            json!({"name":name,"no":true}),
            format!("no interface {name}"),
        ),
        VpnClientChange::Enabled { name, enabled } => toggle(
            if *enabled {
                "interface up"
            } else {
                "interface down"
            },
            name,
            true,
        ),
        VpnClientChange::GenerateWireGuardPrivateKey { name } => context(
            "interface wireguard private-key",
            name,
            json!({}),
            "wireguard private-key".to_owned(),
        ),
        VpnClientChange::WireGuardListenPort { name, port } => context(
            "interface wireguard listen-port",
            name,
            json!({"port":port}),
            format!("wireguard listen-port {port}"),
        ),
        VpnClientChange::WireGuardPeer { name, public_key } => context(
            "interface wireguard peer",
            name,
            json!({"key":public_key}),
            format!("wireguard peer {public_key}"),
        ),
        VpnClientChange::WireGuardEndpoint {
            name,
            public_key,
            address,
            port,
        } => peer_context(
            "interface wireguard peer endpoint",
            name,
            public_key,
            json!({"address":address,"port":port}),
            format!("endpoint {address} {port}"),
        ),
        VpnClientChange::WireGuardAllowedIp {
            name,
            public_key,
            address,
            mask,
        } => peer_context(
            "interface wireguard peer allow-ips",
            name,
            public_key,
            json!({"address":address,"mask":mask}),
            format!("allow-ips {address} {mask}"),
        ),
        VpnClientChange::WireGuardKeepalive {
            name,
            public_key,
            seconds,
        } => peer_context(
            "interface wireguard peer keepalive-interval",
            name,
            public_key,
            json!({"interval":seconds}),
            format!("keepalive-interval {seconds}"),
        ),
        VpnClientChange::WireGuardAsc { name, asc } => context(
            "interface wireguard asc",
            name,
            asc_body(&asc.values),
            format!("wireguard asc {}", asc.values.join(" ")),
        ),
        VpnClientChange::ZeroTierNetwork { name, network_id } => context(
            "interface zerotier network-id",
            name,
            json!({"network-id":network_id}),
            format!("zerotier network-id {network_id}"),
        ),
        VpnClientChange::ZeroTierAcceptAddresses { name, enabled } => {
            toggle("interface zerotier accept-addresses", name, *enabled)
        }
        VpnClientChange::ZeroTierAcceptRoutes { name, enabled } => {
            toggle("interface zerotier accept-routes", name, *enabled)
        }
        VpnClientChange::OpenVpnAcceptRoutes { name, enabled } => {
            toggle("interface openvpn accept-routes", name, *enabled)
        }
        VpnClientChange::OpenVpnNameServers { name, enabled } => {
            toggle("interface openvpn name-servers", name, *enabled)
        }
        VpnClientChange::OpenConnectProtocol { name, protocol } => context(
            "interface openconnect protocol",
            name,
            json!({"protocol":protocol}),
            format!("openconnect protocol {protocol}"),
        ),
        VpnClientChange::OpenConnectAcceptAddresses { name, enabled } => {
            toggle("interface openconnect accept-addresses", name, *enabled)
        }
        VpnClientChange::OpenConnectAcceptRoutes { name, enabled } => {
            toggle("interface openconnect accept-routes", name, *enabled)
        }
        VpnClientChange::ProxyProtocol { name, protocol } => context(
            "interface proxy protocol",
            name,
            json!({"protocol":protocol}),
            format!("proxy protocol {protocol}"),
        ),
        VpnClientChange::ProxyUpstream { name, host, port } => context(
            "interface proxy upstream",
            name,
            port.map_or_else(
                || json!({"host":host}),
                |upstream_port| json!({"host":host,"port":upstream_port}),
            ),
            port.map_or_else(
                || format!("proxy upstream {host}"),
                |upstream_port| format!("proxy upstream {host} {upstream_port}"),
            ),
        ),
        VpnClientChange::IkePolicy { name } => named("crypto ike policy", name),
        VpnClientChange::IkeProposal { name } => named("crypto ike proposal", name),
        VpnClientChange::IpsecProfile { name } => named("crypto ipsec profile", name),
        VpnClientChange::IpsecTransformSet { name } => named("crypto ipsec transform-set", name),
        VpnClientChange::CryptoMap { name } => named("crypto map", name),
    }
}

fn validate(router: &RouterCtx, path: &str, body: &Value) -> Result<ValidatedRequest> {
    router
        .catalog
        .validate(path, HttpMethod::Post, body)
        .map_err(|issues| DomainError::Validation { issues })
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "rendered leaves are temporary owned strings moved into the final CLI line"
)]
fn context(
    path: &'static str,
    name: &str,
    body: Value,
    leaf: String,
) -> (&'static str, Value, String) {
    (path, body, format!("interface {name} {leaf}"))
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "rendered leaves are temporary owned strings moved into the contextual CLI line"
)]
fn peer_context(
    path: &'static str,
    name: &str,
    public_key: &str,
    body: Value,
    leaf: String,
) -> (&'static str, Value, String) {
    context(
        path,
        name,
        body,
        format!("wireguard peer {public_key} {leaf}"),
    )
}

fn toggle(path: &'static str, name: &str, enabled: bool) -> (&'static str, Value, String) {
    let leaf = path.strip_prefix("interface ").unwrap_or(path);
    context(
        path,
        name,
        if enabled {
            json!({})
        } else {
            json!({"no":true})
        },
        if enabled {
            leaf.to_owned()
        } else {
            format!("no {leaf}")
        },
    )
}

fn named(path: &'static str, name: &str) -> (&'static str, Value, String) {
    (path, json!({"name":name}), format!("{path} {name}"))
}

fn asc_body(values: &[String]) -> Value {
    const FIELDS: [&str; 16] = [
        "jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4", "s3", "s4", "i1", "i2", "i3",
        "i4", "i5",
    ];
    let map = FIELDS
        .iter()
        .zip(values)
        .map(|(field, value)| ((*field).to_owned(), Value::String(value.clone())))
        .collect::<serde_json::Map<_, _>>();
    Value::Object(map)
}

fn parse_endpoint(endpoint: &str) -> Result<(String, u16)> {
    let (address, port) = endpoint
        .rsplit_once(':')
        .ok_or(DomainError::InvalidResponse)?;
    Ok((
        address.trim_matches(['[', ']']).to_owned(),
        port.parse::<u16>()
            .map_err(|_error| DomainError::InvalidResponse)?,
    ))
}

fn parse_prefix(prefix: &str) -> Result<(String, String)> {
    let (address, prefix_length) = prefix.split_once('/').ok_or(DomainError::InvalidResponse)?;
    let bits = prefix_length
        .parse::<u32>()
        .map_err(|_error| DomainError::InvalidResponse)?;
    if address.contains(':') {
        return Ok((address.to_owned(), bits.to_string()));
    }
    if bits > 32 {
        return Err(DomainError::InvalidResponse);
    }
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX
            .checked_shl(32_u32.saturating_sub(bits))
            .ok_or(DomainError::InvalidResponse)?
    };
    Ok((
        address.to_owned(),
        format!(
            "{}.{}.{}.{}",
            mask >> 24,
            (mask >> 16) & 255,
            (mask >> 8) & 255,
            mask & 255
        ),
    ))
}

const fn operation(name: &'static str, catalog_path: &'static str) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk: Risk::Write,
        permission: Permission::Write,
        persists_immediately: false,
    }
}
