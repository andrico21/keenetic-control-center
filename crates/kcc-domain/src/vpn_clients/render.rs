//! Non-secret VPN client command rendering.

use kcc_catalog::ValidationIssue;
use serde_json::{Value, json};

use super::VpnClientChange;
use crate::{
    DomainError, Result,
    cli_token::{quoted, token},
};

/// A catalog path, its body and the CLI line that renders it.
type Rendered = (&'static str, Value, String);

/// The catalog path, the body and the CLI line of one VPN client change.
///
/// # Errors
///
/// Returns [`DomainError::InvalidCliToken`] when a name, key or value cannot be one safe
/// CLI word, and [`DomainError::Validation`] for more ASC values than the router takes.
pub(super) fn input(change: &VpnClientChange) -> Result<Rendered> {
    Ok(match change {
        VpnClientChange::Create { name } => (
            "interface",
            json!({"name":name}),
            format!("interface {}", token(name)?),
        ),
        VpnClientChange::Delete { name } => (
            "interface",
            json!({"name":name,"no":true}),
            format!("no interface {}", token(name)?),
        ),
        VpnClientChange::Enabled { name, enabled } => enabled_interface(name, *enabled)?,
        VpnClientChange::GenerateWireGuardPrivateKey { name } => context(
            "interface wireguard private-key",
            name,
            json!({}),
            "wireguard private-key".to_owned(),
        )?,
        VpnClientChange::WireGuardListenPort { name, port } => context(
            "interface wireguard listen-port",
            name,
            json!({"port":port}),
            format!("wireguard listen-port {port}"),
        )?,
        VpnClientChange::WireGuardPeer { name, public_key } => context(
            "interface wireguard peer",
            name,
            json!({"key":public_key}),
            format!("wireguard peer {}", token(public_key)?),
        )?,
        VpnClientChange::WireGuardEndpoint {
            name,
            public_key,
            address,
            port,
        } => peer_endpoint(name, public_key, address, *port)?,
        VpnClientChange::WireGuardAllowedIp {
            name,
            public_key,
            address,
            mask,
        } => peer_address(name, public_key, address, mask)?,
        VpnClientChange::WireGuardKeepalive {
            name,
            public_key,
            seconds,
        } => peer_keepalive(name, public_key, *seconds)?,
        VpnClientChange::WireGuardAsc { name, asc } => context(
            "interface wireguard asc",
            name,
            asc_body(&asc.values),
            asc_line(&asc.values)?,
        )?,
        VpnClientChange::ZeroTierNetwork { name, network_id } => context(
            "interface zerotier network-id",
            name,
            json!({"network-id":network_id}),
            format!("zerotier network-id {}", token(network_id)?),
        )?,
        VpnClientChange::ZeroTierAcceptAddresses { name, enabled } => {
            toggle("interface zerotier accept-addresses", name, *enabled)?
        }
        VpnClientChange::ZeroTierAcceptRoutes { name, enabled } => {
            toggle("interface zerotier accept-routes", name, *enabled)?
        }
        VpnClientChange::OpenVpnAcceptRoutes { name, enabled } => {
            toggle("interface openvpn accept-routes", name, *enabled)?
        }
        VpnClientChange::OpenVpnNameServers { name, enabled } => {
            toggle("interface openvpn name-servers", name, *enabled)?
        }
        VpnClientChange::OpenConnectProtocol { name, protocol } => context(
            "interface openconnect protocol",
            name,
            json!({"protocol":protocol}),
            format!("openconnect protocol {}", token(protocol)?),
        )?,
        VpnClientChange::OpenConnectAcceptAddresses { name, enabled } => {
            toggle("interface openconnect accept-addresses", name, *enabled)?
        }
        VpnClientChange::OpenConnectAcceptRoutes { name, enabled } => {
            toggle("interface openconnect accept-routes", name, *enabled)?
        }
        VpnClientChange::ProxyProtocol { name, protocol } => context(
            "interface proxy protocol",
            name,
            json!({"protocol":protocol}),
            format!("proxy protocol {}", token(protocol)?),
        )?,
        VpnClientChange::ProxyUpstream { name, host, port } => proxy_upstream(name, host, *port)?,
        VpnClientChange::IkePolicy { name } => named("crypto ike policy", name)?,
        VpnClientChange::IkeProposal { name } => named("crypto ike proposal", name)?,
        VpnClientChange::IpsecProfile { name } => named("crypto ipsec profile", name)?,
        VpnClientChange::IpsecTransformSet { name } => named("crypto ipsec transform-set", name)?,
        VpnClientChange::CryptoMap { name } => named("crypto map", name)?,
    })
}

/// Renders enabling or disabling the interface `name`.
///
/// # Errors
///
/// Returns [`DomainError::InvalidCliToken`] when the name is not one safe CLI word.
fn enabled_interface(name: &str, enabled: bool) -> Result<Rendered> {
    let path = if enabled {
        "interface up"
    } else {
        "interface down"
    };
    toggle(path, name, true)
}

/// Renders `leaf` under the `interface <name>` context.
///
/// # Errors
///
/// Returns [`DomainError::InvalidCliToken`] when the name is not one safe CLI word.
#[expect(
    clippy::needless_pass_by_value,
    reason = "rendered leaves are temporary owned strings moved into the final CLI line"
)]
fn context(path: &'static str, name: &str, body: Value, leaf: String) -> Result<Rendered> {
    Ok((path, body, format!("interface {} {leaf}", token(name)?)))
}

/// Renders `command` under the WireGuard peer `public_key` of the interface `name`.
///
/// # Errors
///
/// Returns [`DomainError::InvalidCliToken`] when the name or the key is not one safe CLI
/// word.
fn peer_context(name: &str, public_key: &str, command: Rendered) -> Result<Rendered> {
    let (path, body, leaf) = command;
    context(
        path,
        name,
        body,
        format!("wireguard peer {} {leaf}", token(public_key)?),
    )
}

/// Renders a WireGuard peer endpoint.
///
/// # Errors
///
/// Returns [`DomainError::InvalidCliToken`] when a name, key or address is not one safe
/// CLI word.
fn peer_endpoint(name: &str, public_key: &str, address: &str, port: u16) -> Result<Rendered> {
    peer_context(
        name,
        public_key,
        (
            "interface wireguard peer endpoint",
            json!({"address":address,"port":port}),
            format!("endpoint {} {port}", token(address)?),
        ),
    )
}

/// Renders a WireGuard peer allowed range.
///
/// # Errors
///
/// Returns [`DomainError::InvalidCliToken`] when a name, key, address or mask is not one
/// safe CLI word.
fn peer_address(name: &str, public_key: &str, address: &str, mask: &str) -> Result<Rendered> {
    peer_context(
        name,
        public_key,
        (
            "interface wireguard peer allow-ips",
            json!({"address":address,"mask":mask}),
            format!("allow-ips {} {}", token(address)?, token(mask)?),
        ),
    )
}

/// Renders a WireGuard peer keepalive interval.
///
/// # Errors
///
/// Returns [`DomainError::InvalidCliToken`] when the name or the key is not one safe CLI
/// word.
fn peer_keepalive(name: &str, public_key: &str, seconds: u16) -> Result<Rendered> {
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

/// Renders the upstream proxy of the interface `name`.
///
/// # Errors
///
/// Returns [`DomainError::InvalidCliToken`] when the name or the host is not one safe CLI
/// word.
fn proxy_upstream(name: &str, host: &str, port: Option<u16>) -> Result<Rendered> {
    let upstream = token(host)?;
    context(
        "interface proxy upstream",
        name,
        port.map_or_else(
            || json!({"host":upstream}),
            |upstream_port| json!({"host":upstream,"port":upstream_port}),
        ),
        port.map_or_else(
            || format!("proxy upstream {upstream}"),
            |upstream_port| format!("proxy upstream {upstream} {upstream_port}"),
        ),
    )
}

/// Renders switching `path` on or off for the interface `name`.
///
/// # Errors
///
/// Returns [`DomainError::InvalidCliToken`] when the name is not one safe CLI word.
fn toggle(path: &'static str, name: &str, enabled: bool) -> Result<Rendered> {
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

/// Renders `path` for the interface `name`.
///
/// # Errors
///
/// Returns [`DomainError::InvalidCliToken`] when the name is not one safe CLI word.
fn named(path: &'static str, name: &str) -> Result<Rendered> {
    Ok((
        path,
        json!({"name":name}),
        format!("{path} {}", token(name)?),
    ))
}

/// The quoted ASC values of a WireGuard interface.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] for more than sixteen values and
/// [`DomainError::InvalidCliToken`] when a value cannot be quoted.
fn asc_line(values: &[String]) -> Result<String> {
    if values.len() > ASC_FIELDS.len() {
        return Err(DomainError::Validation {
            issues: vec![ValidationIssue::InvalidValue {
                field: "values".to_owned(),
            }],
        });
    }
    let words = values
        .iter()
        .map(|value| quoted(value))
        .collect::<Result<Vec<_>>>()?;
    Ok(format!("wireguard asc {}", words.join(" ")))
}

/// The catalog names of the ASC values, in CLI order.
const ASC_FIELDS: [&str; 16] = [
    "jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4", "s3", "s4", "i1", "i2", "i3", "i4",
    "i5",
];

/// The catalog body of the ASC values.
fn asc_body(values: &[String]) -> Value {
    let map = ASC_FIELDS
        .iter()
        .zip(values)
        .map(|(field, value)| ((*field).to_owned(), Value::String(value.clone())))
        .collect::<serde_json::Map<_, _>>();
    Value::Object(map)
}
