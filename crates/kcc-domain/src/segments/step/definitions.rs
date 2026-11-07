//! Bridge, pool, and optional binding step definitions.

use serde_json::json;

use super::{SegmentSpec, Step, StepVerification, step};

/// Builds bridge, DHCP, NAT, and hotspot steps.
pub(super) fn core_steps(segment: &SegmentSpec, vlan: &str, bridge: &str, pool: &str) -> [Step; 5] {
    [
        step(
            "bridge".to_owned(),
            "interface ip address",
            json!({"address":segment.address.to_string(),"mask":segment.mask.to_string()}),
            format!(
                "interface {bridge} ip address {} {}",
                segment.address, segment.mask
            ),
            format!("no interface {bridge}"),
            StepVerification {
                context: format!("interface {bridge}"),
                child: Some(format!("ip address {} {}", segment.address, segment.mask)),
                cleanup_context: None,
            },
        ),
        step(
            "bridge-vlan".to_owned(),
            "interface include",
            json!({"interface":vlan}),
            format!("interface {bridge} include {vlan}"),
            format!("no interface {bridge} include {vlan}"),
            StepVerification {
                context: format!("interface {bridge}"),
                child: Some(format!("include {vlan}")),
                cleanup_context: None,
            },
        ),
        step(
            "dhcp-pool".to_owned(),
            "ip dhcp pool range",
            json!({"begin":segment.dhcp_begin.to_string(),"end":segment.dhcp_end.to_string()}),
            format!(
                "ip dhcp pool {pool} range {} {}",
                segment.dhcp_begin, segment.dhcp_end
            ),
            format!("no ip dhcp pool {pool}"),
            StepVerification {
                context: format!("ip dhcp pool {pool}"),
                child: Some(format!("range {} {}", segment.dhcp_begin, segment.dhcp_end)),
                cleanup_context: None,
            },
        ),
        step(
            "nat".to_owned(),
            "ip nat",
            json!({"interface":bridge}),
            format!("ip nat {bridge}"),
            format!("no ip nat {bridge}"),
            StepVerification {
                context: format!("ip nat {bridge}"),
                child: None,
                cleanup_context: None,
            },
        ),
        step(
            "hotspot-policy".to_owned(),
            "ip hotspot policy",
            json!({"interface":bridge,"access":"permit"}),
            format!("ip hotspot policy {bridge} permit"),
            format!("no ip hotspot policy {bridge} permit"),
            StepVerification {
                context: format!("ip hotspot policy {bridge} permit"),
                child: None,
                cleanup_context: None,
            },
        ),
    ]
}

/// Appends optional Wi-Fi and connection-policy steps.
pub(super) fn append_optional_steps(
    definitions: &mut Vec<Step>,
    segment: &SegmentSpec,
    bridge: &str,
) {
    if let Some(access_point) = &segment.access_point {
        definitions.push(step(
            "wifi-binding".to_owned(),
            "interface include",
            json!({"interface":access_point}),
            format!("interface {bridge} include {access_point}"),
            format!("no interface {bridge} include {access_point}"),
            StepVerification {
                context: format!("interface {bridge}"),
                child: Some(format!("include {access_point}")),
                cleanup_context: None,
            },
        ));
    }
    if let Some(policy) = &segment.connection_policy {
        definitions.push(step(
            "connection-policy".to_owned(),
            "ip policy description",
            json!({"description":"segment"}),
            format!("ip policy {policy} description segment"),
            format!("no ip policy {policy}"),
            StepVerification {
                context: format!("ip policy {policy}"),
                child: Some("description segment".to_owned()),
                cleanup_context: None,
            },
        ));
    }
}
