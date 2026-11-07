//! Secret-free VPN status decoding.

use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{VpnClientStatus, VpnClientType};

/// Decodes supported VPN interfaces while dropping every unknown field.
pub(super) fn decode_clients(value: &Value) -> Vec<VpnClientStatus> {
    let root = value.pointer("/show/interface").unwrap_or(value);
    root.as_object()
        .into_iter()
        .flat_map(serde_json::Map::iter)
        .filter_map(|(name, item)| decode_client(name, item))
        .collect()
}

/// Selects the documented client type and its closed read model.
fn decode_client(name: &str, value: &Value) -> Option<VpnClientStatus> {
    let client_type = match value.get("type")?.as_str()?.to_ascii_lowercase().as_str() {
        "wireguard" => VpnClientType::WireGuard,
        "openvpn" => VpnClientType::OpenVpn,
        "ipsec" => VpnClientType::Ipsec,
        "l2tp" | "l2tp/ipsec" => VpnClientType::L2tpIpsec,
        "pptp" => VpnClientType::Pptp,
        "sstp" => VpnClientType::Sstp,
        "zerotier" => VpnClientType::ZeroTier,
        "openconnect" => VpnClientType::OpenConnect,
        "proxy" => VpnClientType::Proxy,
        _ => return None,
    };
    Some(VpnClientStatus {
        id: value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_owned(),
        client_type,
        state: value
            .get("state")
            .and_then(Value::as_str)
            .map(str::to_owned),
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

/// Ignores unknown fields by deserializing only the selected typed projection.
fn decode_for<T>(actual: VpnClientType, expected: VpnClientType, value: &Value) -> Option<T>
where
    T: DeserializeOwned,
{
    (actual == expected)
        .then(|| serde_json::from_value(value.clone()).ok())
        .flatten()
}
