//! Non-secret VPN client command rendering.
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private conversion helpers directly mirror catalog command names"
    )
)]

use serde_json::{Value, json};

use super::VpnClientChange;

pub(super) fn input(change: &VpnClientChange) -> (&'static str, Value, String) {
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
        VpnClientChange::Enabled { name, enabled } => enabled_interface(name, *enabled),
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
        } => peer_endpoint(name, public_key, address, *port),
        VpnClientChange::WireGuardAllowedIp {
            name,
            public_key,
            address,
            mask,
        } => peer_address(name, public_key, address, mask),
        VpnClientChange::WireGuardKeepalive {
            name,
            public_key,
            seconds,
        } => peer_keepalive(name, public_key, *seconds),
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
        VpnClientChange::ProxyUpstream { name, host, port } => proxy_upstream(name, host, *port),
        VpnClientChange::IkePolicy { name } => named("crypto ike policy", name),
        VpnClientChange::IkeProposal { name } => named("crypto ike proposal", name),
        VpnClientChange::IpsecProfile { name } => named("crypto ipsec profile", name),
        VpnClientChange::IpsecTransformSet { name } => named("crypto ipsec transform-set", name),
        VpnClientChange::CryptoMap { name } => named("crypto map", name),
    }
}

fn enabled_interface(name: &str, enabled: bool) -> (&'static str, Value, String) {
    let path = if enabled {
        "interface up"
    } else {
        "interface down"
    };
    toggle(path, name, true)
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

fn peer_context(
    name: &str,
    public_key: &str,
    command: (&'static str, Value, String),
) -> (&'static str, Value, String) {
    let (path, body, leaf) = command;
    context(
        path,
        name,
        body,
        format!("wireguard peer {public_key} {leaf}"),
    )
}

fn peer_endpoint(
    name: &str,
    public_key: &str,
    address: &str,
    port: u16,
) -> (&'static str, Value, String) {
    peer_context(
        name,
        public_key,
        (
            "interface wireguard peer endpoint",
            json!({"address":address,"port":port}),
            format!("endpoint {address} {port}"),
        ),
    )
}

fn peer_address(
    name: &str,
    public_key: &str,
    address: &str,
    mask: &str,
) -> (&'static str, Value, String) {
    peer_context(
        name,
        public_key,
        (
            "interface wireguard peer allow-ips",
            json!({"address":address,"mask":mask}),
            format!("allow-ips {address} {mask}"),
        ),
    )
}

fn peer_keepalive(name: &str, public_key: &str, seconds: u16) -> (&'static str, Value, String) {
    peer_context(
        name,
        public_key,
        (
            "interface wireguard peer keepalive-interval",
            json!({"interval":seconds}),
            format!("keepalive-interval {seconds}"),
        ),
    )
}

fn proxy_upstream(name: &str, host: &str, port: Option<u16>) -> (&'static str, Value, String) {
    context(
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
