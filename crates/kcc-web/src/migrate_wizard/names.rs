//! Object names in a source configuration: its interface contexts, which of them are
//! ports or radios, what a valid interface name is, and the kind a name implies.

use alloc::collections::BTreeSet;

use kcc_config::config_text::Token;
use kcc_migrate::{inventory::PhysicalPort, source::SourceConfig};

/// The names of the source configuration's interface contexts, in order.
pub(super) fn configured_interfaces(config: &SourceConfig) -> Vec<String> {
    let mut seen = BTreeSet::new();
    config
        .ast
        .nodes
        .iter()
        .filter_map(|node| match node.tokens.as_slice() {
            [Token::Word(command), Token::Word(name), ..] if command == "interface" => {
                Some(name.clone())
            }
            _ => None,
        })
        .filter(|name| seen.insert(name.clone()))
        .collect()
}

/// Whether a configured `name` is one of the target's ports or looks like a port.
pub(super) fn is_port(name: &str, ports: &[PhysicalPort]) -> bool {
    ports.iter().any(|port| port.id == name)
        || (name.contains("Ethernet") && !name.contains("/AccessPoint"))
}

/// Whether a configured `name` is a Wi-Fi radio (not one of its access points).
pub(super) fn is_radio(name: &str) -> bool {
    name.strip_prefix("WifiMaster")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Whether `name` can name an interface: 1 to 64 Latin letters, digits and `/_.-`,
/// starting with a letter.
pub(super) fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name.starts_with(|first: char| first.is_ascii_alphabetic())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'.' | b'-'))
}

/// The interface kind a name implies, as the engine infers it for target interfaces.
pub(super) fn interface_kind(name: &str) -> &'static str {
    [
        "Bridge",
        "Vlan",
        "PPPoE",
        "Wireguard",
        "UsbModem",
        "OpenVPN",
        "SSTP",
        "L2TP",
        "PPTP",
        "IPSec",
    ]
    .into_iter()
    .find(|prefix| name.starts_with(prefix))
    .unwrap_or("Other")
}
