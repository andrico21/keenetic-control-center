//! Object names in a source configuration: its interface contexts, which of them are
//! ports or radios, what a valid interface name is, the kind a name implies, and the
//! engine's maps of them.

use alloc::collections::BTreeSet;

use kcc_config::config_text::Token;
use kcc_migrate::{inventory::PhysicalPort, maps::MapEntry, source::SourceConfig};

/// The names of the source configuration's interface contexts, in order.
pub(crate) fn configured_interfaces(config: &SourceConfig) -> Vec<String> {
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
pub(crate) fn is_port(name: &str, ports: &[PhysicalPort]) -> bool {
    ports.iter().any(|port| port.id == name)
        || (name.contains("Ethernet") && !name.contains("/AccessPoint"))
        || is_switch_port(name)
}

/// Whether a configured `name` is a switch port by its number, as in
/// `interface 1 switchport trunk vlan 5`: a port, never a typed interface name.
pub(crate) fn is_switch_port(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether a configured `name` is a Wi-Fi radio (not one of its access points).
pub(crate) fn is_radio(name: &str) -> bool {
    name.strip_prefix("WifiMaster")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Whether `name` can name an interface: 1 to 64 Latin letters, digits and `/_.-`,
/// starting with a letter.
pub(crate) fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name.starts_with(|first: char| first.is_ascii_alphabetic())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'.' | b'-'))
}

/// The interface kind a name implies, as the engine infers it for target interfaces.
pub(crate) fn interface_kind(name: &str) -> &'static str {
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

/// One of the engine's maps from `(source, target)` pairs, in order.
pub(crate) fn map_of<M, I>(pairs: I) -> M
where
    M: FromIterator<MapEntry>,
    I: IntoIterator<Item = (String, Option<String>)>,
{
    pairs
        .into_iter()
        .map(|(source, target)| MapEntry::new(source, target))
        .collect()
}
