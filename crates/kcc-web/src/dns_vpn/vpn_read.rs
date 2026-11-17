//! What the VPN tabs show, read through the VPN client and server domains: connections
//! by type with their state, WireGuard peers, and the servers with their settings.
//!
//! The domains never return a secret: key and password fields arrive as presence
//! markers only, and that is all the pages show of them.

use core::net::Ipv4Addr;

use fluent_bundle::{FluentArgs, FluentValue};
use kcc_domain::{
    Result as DomainResult, RouterCtx,
    vpn_clients::{self, VpnClientStatus, VpnClientType, WireGuardPeerStatus},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde_json::Value;

/// The label of a connection type.
pub(crate) const fn type_label(kind: VpnClientType) -> MessageKey {
    match kind {
        VpnClientType::WireGuard => keys::WEB_VPN_TYPE_WIREGUARD,
        VpnClientType::OpenVpn => keys::WEB_VPN_TYPE_OPENVPN,
        VpnClientType::Ipsec => keys::WEB_VPN_TYPE_IPSEC,
        VpnClientType::L2tpIpsec => keys::WEB_VPN_TYPE_L2TP,
        VpnClientType::Pptp => keys::WEB_VPN_TYPE_PPTP,
        VpnClientType::Sstp => keys::WEB_VPN_TYPE_SSTP,
        VpnClientType::ZeroTier => keys::WEB_VPN_TYPE_ZEROTIER,
        VpnClientType::OpenConnect => keys::WEB_VPN_TYPE_OPENCONNECT,
        VpnClientType::Proxy => keys::WEB_VPN_TYPE_PROXY,
        _ => keys::WEB_VPN_TYPE_OTHER,
    }
}

/// Whether a connection is up: `Some(true)` for `up`, `Some(false)` for `down`.
pub(crate) fn is_up(client: &VpnClientStatus) -> Option<bool> {
    match client.state.as_deref() {
        Some("up") => Some(true),
        Some("down") => Some(false),
        Some(_) | None => None,
    }
}

/// What a connection's row says about it beyond its type and state.
pub(crate) fn details(client: &VpnClientStatus, locale: Locale) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(wireguard) = &client.wireguard {
        if let Some(port) = &wireguard.listen_port {
            lines.push(said(
                locale,
                keys::WEB_VPN_DETAIL_PORT,
                ("port", port.clone()),
            ));
        }
        let count = wireguard.peers.len();
        lines.push(said(locale, keys::WEB_VPN_DETAIL_PEERS, ("count", count)));
    }
    let peers = [&client.l2tp_ipsec, &client.pptp, &client.sstp]
        .into_iter()
        .flatten()
        .filter_map(|ppp| ppp.peer.clone())
        .chain(client.ipsec.as_ref().and_then(|ipsec| ipsec.peer.clone()));
    lines.extend(peers.map(|peer| said(locale, keys::WEB_VPN_DETAIL_PEER, ("peer", peer))));
    if let Some(network) = client
        .zerotier
        .as_ref()
        .and_then(|zerotier| zerotier.network_id.clone())
    {
        lines.push(said(
            locale,
            keys::WEB_VPN_DETAIL_NETWORK,
            ("network", network),
        ));
    }
    let protocol = client
        .openconnect
        .as_ref()
        .and_then(|openconnect| openconnect.protocol.clone())
        .or_else(|| client.proxy.as_ref()?.protocol.clone());
    if let Some(name) = protocol {
        lines.push(said(
            locale,
            keys::WEB_VPN_DETAIL_PROTOCOL,
            ("protocol", name),
        ));
    }
    lines
}

/// `key` in `locale` with the one variable `(name, value)`.
fn said<V>(locale: Locale, key: MessageKey, (name, value): (&'static str, V)) -> String
where
    V: Into<FluentValue<'static>>,
{
    let mut args = FluentArgs::new();
    args.set(name, value);
    tr(locale, key, Some(&args))
}

/// Whether the router has a VPN connection named `name`.
///
/// # Errors
///
/// Returns the domain's error when the connections cannot be read.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
pub(crate) async fn exists(ctx: &RouterCtx, name: &str) -> DomainResult<bool> {
    let clients = vpn_clients::read_clients(ctx).await?;
    Ok(clients.iter().any(|client| client.id == name))
}

/// The first `Wireguard<N>` name no connection uses.
pub(crate) fn free_wireguard(clients: &[VpnClientStatus]) -> String {
    let used: Vec<u16> = clients
        .iter()
        .filter_map(|client| client.id.strip_prefix("Wireguard")?.parse().ok())
        .collect();
    let free = (0_u16..1000)
        .find(|number| !used.contains(number))
        .unwrap_or(0);
    format!("Wireguard{free}")
}

/// The endpoint of a peer as `address:port`.
pub(crate) fn endpoint(peer: &WireGuardPeerStatus) -> Option<String> {
    match peer.endpoint.as_deref()? {
        [address, port] if address.contains(':') => Some(format!("[{address}]:{port}")),
        [address, port] => Some(format!("{address}:{port}")),
        parts => (!parts.is_empty()).then(|| parts.join(" ")),
    }
}

/// The allowed addresses of a peer, as `address/bits` where the mask allows it.
pub(crate) fn allowed(peer: &WireGuardPeerStatus) -> Vec<String> {
    let parts = peer.allowed_ips.as_deref().unwrap_or_default();
    parts
        .chunks(2)
        .map(|pair| match pair {
            [address, mask] => prefix(mask).map_or_else(
                || format!("{address} {mask}"),
                |bits| format!("{address}/{bits}"),
            ),
            single => single.join(" "),
        })
        .collect()
}

/// The prefix length of a dotted IPv4 `mask`, or of a mask that already is one.
fn prefix(mask: &str) -> Option<u32> {
    if let Ok(bits) = mask.parse::<u32>() {
        return Some(bits);
    }
    let address: Ipv4Addr = mask.parse().ok()?;
    let bits = u32::from(address);
    (bits.leading_ones() == bits.count_ones()).then(|| bits.count_ones())
}

/// A server setting as text: a string, a number, or the values of a list or an object.
pub(crate) fn shown(value: Option<&Value>) -> Option<String> {
    let text = match value? {
        Value::String(string) => string.clone(),
        Value::Number(number) => number.to_string(),
        Value::Array(items) => items
            .iter()
            .filter_map(|item| shown(Some(item)))
            .collect::<Vec<_>>()
            .join(", "),
        Value::Object(members) => members
            .values()
            .filter_map(|item| shown(Some(item)))
            .collect::<Vec<_>>()
            .join(" "),
        Value::Bool(_) | Value::Null => String::new(),
    };
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_domain::vpn_clients::WireGuardPeerStatus;
    use serde_json::json;

    use super::{allowed, endpoint, shown};

    #[test]
    fn peers_read_as_people_write_them() {
        let peer: WireGuardPeerStatus = serde_json::from_value(json!({
            "public-key": "key", "endpoint": ["198.51.100.7", "51820"],
            "allow-ips": ["192.0.2.0", "255.255.255.0", "0.0.0.0", "0.0.0.0", "10.0.0.0", "255.0.255.0"]
        }))
        .unwrap_or_default();
        assert_eq!(
            endpoint(&peer).as_deref(),
            Some("198.51.100.7:51820"),
            "endpoint"
        );
        assert_eq!(
            allowed(&peer),
            ["192.0.2.0/24", "0.0.0.0/0", "10.0.0.0 255.0.255.0"],
            "prefixes, a gappy mask as written"
        );
        assert_eq!(
            shown(Some(&json!({"begin": "192.0.2.33", "size": 10_i32}))).as_deref(),
            Some("192.0.2.33 10"),
            "object"
        );
        assert_eq!(shown(Some(&json!(true))), None, "nothing to show");
    }
}
