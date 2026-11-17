//! Non-secret VPN server command rendering.

use kcc_catalog::ValidationIssue;
use serde_json::{Value, json};

use super::{VpnServerChange, VpnServerService};
use crate::{DomainError, Result};

/// A server with an address pool and DNS servers of its own.
#[derive(Clone, Copy)]
enum ServerKind {
    /// The PPTP/L2TP server.
    Vpn,
    /// The SSTP server.
    Sstp,
    /// The OpenConnect server.
    OpenConnect,
}

impl ServerKind {
    /// The command prefix of the server's settings.
    const fn prefix(self) -> &'static str {
        match self {
            Self::Vpn => "vpn-server",
            Self::Sstp => "sstp-server",
            Self::OpenConnect => "oc-server",
        }
    }

    /// The catalog path of the server's address pool.
    const fn pool_path(self) -> &'static str {
        match self {
            Self::Vpn => "vpn-server pool-range",
            Self::Sstp => "sstp-server pool-range",
            Self::OpenConnect => "oc-server pool-range",
        }
    }

    /// The catalog path of the server's DNS servers.
    const fn dns_path(self) -> &'static str {
        match self {
            Self::Vpn => "vpn-server dns-servers",
            Self::Sstp => "sstp-server dns-servers",
            Self::OpenConnect => "oc-server dns-servers",
        }
    }
}

/// Maps the closed operation vocabulary to catalog arguments and a CLI line.
///
/// # Errors
///
/// Refuses a virtual-IP pool that has neither or both of its end address and size as an
/// invalid `end`.
pub(super) fn input(change: &VpnServerChange) -> Result<(&'static str, Value, String)> {
    Ok(match change {
        VpnServerChange::Service { service, enabled } => service_toggle(*service, *enabled),
        VpnServerChange::VpnInterface { interface } => (
            "vpn-server interface",
            json!({"interface":interface}),
            format!("vpn-server interface {interface}"),
        ),
        VpnServerChange::VpnPool { begin, size } => pool(ServerKind::Vpn, begin, *size),
        VpnServerChange::VpnDns { primary, secondary } => {
            dns(ServerKind::Vpn, primary, secondary.as_deref())
        }
        VpnServerChange::SstpInterface { interface } => (
            "sstp-server interface",
            json!({"interface":interface}),
            format!("sstp-server interface {interface}"),
        ),
        VpnServerChange::SstpPool { begin, size } => pool(ServerKind::Sstp, begin, *size),
        VpnServerChange::SstpDns { primary, secondary } => {
            dns(ServerKind::Sstp, primary, secondary.as_deref())
        }
        VpnServerChange::WireGuardInterface { interface, enabled } => (
            "wireguard-server interface",
            if *enabled {
                json!({"interface":interface})
            } else {
                json!({"interface":interface,"no":true})
            },
            if *enabled {
                format!("wireguard-server interface {interface}")
            } else {
                format!("no wireguard-server interface {interface}")
            },
        ),
        VpnServerChange::OpenConnectInterface { interface } => (
            "oc-server interface",
            json!({"interface":interface}),
            format!("oc-server interface {interface}"),
        ),
        VpnServerChange::OpenConnectPool { begin, size } => {
            pool(ServerKind::OpenConnect, begin, *size)
        }
        VpnServerChange::OpenConnectRoute { address, mask } => (
            "oc-server route",
            json!({"address":address,"mask":mask}),
            format!("oc-server route {address} {mask}"),
        ),
        VpnServerChange::OpenConnectDns { primary, secondary } => {
            dns(ServerKind::OpenConnect, primary, secondary.as_deref())
        }
        VpnServerChange::IpsecMap { name } => (
            "crypto map",
            json!({"name":name}),
            format!("crypto map {name}"),
        ),
        VpnServerChange::IpsecVirtualIp { name, enabled } => (
            "crypto map virtual-ip enable",
            if *enabled {
                json!({})
            } else {
                json!({"no":true})
            },
            if *enabled {
                format!("crypto map {name} virtual-ip enable")
            } else {
                format!("no crypto map {name} virtual-ip enable")
            },
        ),
        VpnServerChange::IpsecVirtualIpPool {
            name,
            begin,
            end,
            size,
        } => virtual_pool(name, begin, end.as_deref(), *size)?,
        VpnServerChange::IpsecVirtualIpDns {
            name,
            primary,
            secondary,
        } => (
            "crypto map virtual-ip dns-servers",
            optional_second("dns1", primary, "dns2", secondary.as_deref()),
            secondary.as_ref().map_or_else(
                || format!("crypto map {name} virtual-ip dns-servers {primary}"),
                |second_dns| {
                    format!("crypto map {name} virtual-ip dns-servers {primary} {second_dns}")
                },
            ),
        ),
    })
}

/// Renders the mutually exclusive end-address and size forms of a virtual-IP pool.
///
/// # Errors
///
/// Refuses a pool with neither or both of `end` and `size` as an invalid `end`.
fn virtual_pool(
    name: &str,
    begin: &str,
    end: Option<&str>,
    size: Option<u16>,
) -> Result<(&'static str, Value, String)> {
    let (body, bound) = match (end, size) {
        (Some(pool_end), None) => (json!({"begin":begin,"end":pool_end}), pool_end.to_owned()),
        (None, Some(pool_size)) => (
            json!({"begin":begin,"size":pool_size}),
            pool_size.to_string(),
        ),
        (None, None) | (Some(_), Some(_)) => {
            return Err(DomainError::Validation {
                issues: vec![ValidationIssue::InvalidValue {
                    field: "end".to_owned(),
                }],
            });
        }
    };
    Ok((
        "crypto map virtual-ip range",
        body,
        format!("crypto map {name} virtual-ip range {begin} {bound}"),
    ))
}

/// Renders the selected service toggle.
fn service_toggle(service: VpnServerService, enabled: bool) -> (&'static str, Value, String) {
    let path = match service {
        VpnServerService::Vpn => "service vpn-server",
        VpnServerService::Sstp => "service sstp-server",
        VpnServerService::Ipsec => "service ipsec",
        VpnServerService::OpenConnect => "service oc-server",
    };
    (
        path,
        if enabled {
            json!({})
        } else {
            json!({"no":true})
        },
        if enabled {
            path.to_owned()
        } else {
            format!("no {path}")
        },
    )
}

/// Renders a server address pool.
fn pool(kind: ServerKind, begin: &str, size: Option<u16>) -> (&'static str, Value, String) {
    let prefix = kind.prefix();
    (
        kind.pool_path(),
        size.map_or_else(
            || json!({"begin":begin}),
            |pool_size| json!({"begin":begin,"size":pool_size}),
        ),
        size.map_or_else(
            || format!("{prefix} pool-range {begin}"),
            |pool_size| format!("{prefix} pool-range {begin} {pool_size}"),
        ),
    )
}

/// Renders server DNS addresses.
fn dns(kind: ServerKind, primary: &str, secondary: Option<&str>) -> (&'static str, Value, String) {
    let prefix = kind.prefix();
    (
        kind.dns_path(),
        optional_second("dns1", primary, "dns2", secondary),
        secondary.map_or_else(
            || format!("{prefix} dns-servers {primary}"),
            |second_dns| format!("{prefix} dns-servers {primary} {second_dns}"),
        ),
    )
}

/// Builds one required and one optional named argument.
fn optional_second(first: &str, value: &str, second: &str, optional: Option<&str>) -> Value {
    let mut body = serde_json::Map::new();
    drop(body.insert(first.to_owned(), Value::String(value.to_owned())));
    if let Some(optional_value) = optional {
        drop(body.insert(second.to_owned(), Value::String(optional_value.to_owned())));
    }
    Value::Object(body)
}
