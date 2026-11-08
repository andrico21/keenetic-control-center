//! Non-secret VPN server command rendering.

use serde_json::{Value, json};

use super::{VpnServerChange, VpnServerService};

/// Maps the closed operation vocabulary to catalog arguments and a CLI line.
pub(super) fn input(change: &VpnServerChange) -> (&'static str, Value, String) {
    match change {
        VpnServerChange::Service { service, enabled } => service_toggle(*service, *enabled),
        VpnServerChange::VpnInterface { interface } => (
            "vpn-server interface",
            json!({"interface":interface}),
            format!("vpn-server interface {interface}"),
        ),
        VpnServerChange::VpnPool { begin, size } => pool("vpn-server", begin, *size),
        VpnServerChange::VpnDns { primary, secondary } => {
            dns("vpn-server", primary, secondary.as_deref())
        }
        VpnServerChange::SstpInterface { interface } => (
            "sstp-server interface",
            json!({"interface":interface}),
            format!("sstp-server interface {interface}"),
        ),
        VpnServerChange::SstpPool { begin, size } => pool("sstp-server", begin, *size),
        VpnServerChange::SstpDns { primary, secondary } => {
            dns("sstp-server", primary, secondary.as_deref())
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
        VpnServerChange::OpenConnectPool { begin, size } => pool("oc-server", begin, *size),
        VpnServerChange::OpenConnectRoute { address, mask } => (
            "oc-server route",
            json!({"address":address,"mask":mask}),
            format!("oc-server route {address} {mask}"),
        ),
        VpnServerChange::OpenConnectDns { primary, secondary } => {
            dns("oc-server", primary, secondary.as_deref())
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
        } => virtual_pool(name, begin, end.as_deref(), *size),
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
    }
}

/// Renders the mutually exclusive end-address and size forms of a virtual-IP pool.
fn virtual_pool(
    name: &str,
    begin: &str,
    end: Option<&str>,
    size: Option<u16>,
) -> (&'static str, Value, String) {
    let body = match (end, size) {
        (Some(pool_end), None) => json!({"begin":begin,"end":pool_end}),
        (None, Some(pool_size)) => json!({"begin":begin,"size":pool_size}),
        (None, None) | (Some(_), Some(_)) => json!({"invalid":true}),
    };
    let suffix = end.map_or_else(
        || size.map_or_else(String::new, |pool_size| format!(" {pool_size}")),
        |pool_end| format!(" {pool_end}"),
    );
    (
        "crypto map virtual-ip range",
        body,
        format!("crypto map {name} virtual-ip range {begin}{suffix}"),
    )
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
fn pool(prefix: &'static str, begin: &str, size: Option<u16>) -> (&'static str, Value, String) {
    let path = match prefix {
        "vpn-server" => "vpn-server pool-range",
        "sstp-server" => "sstp-server pool-range",
        "oc-server" => "oc-server pool-range",
        _ => "",
    };
    (
        path,
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
fn dns(
    prefix: &'static str,
    primary: &str,
    secondary: Option<&str>,
) -> (&'static str, Value, String) {
    let path = match prefix {
        "vpn-server" => "vpn-server dns-servers",
        "sstp-server" => "sstp-server dns-servers",
        "oc-server" => "oc-server dns-servers",
        _ => "",
    };
    (
        path,
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
