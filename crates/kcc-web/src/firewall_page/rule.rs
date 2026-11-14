//! What the page shows of a firewall rule in the structured form: the labels of its
//! decision and protocol, and each side's address as people read it.

use core::net::Ipv4Addr;

use kcc_domain::firewall::{
    model::{Action, Protocol},
    rule_words::Side,
};
use kcc_i18n::{bundle::MessageKey, keys};

/// The protocols a rule may name, in the order the Add rule dialog offers them, with
/// their labels.
pub(crate) const PROTOCOLS: [(Protocol, MessageKey); 7] = [
    (Protocol::Tcp, keys::WEB_ROUTING_PROTOCOL_TCP),
    (Protocol::Udp, keys::WEB_ROUTING_PROTOCOL_UDP),
    (Protocol::Icmp, keys::WEB_ROUTING_PROTOCOL_ICMP),
    (Protocol::Esp, keys::WEB_ROUTING_PROTOCOL_ESP),
    (Protocol::Gre, keys::WEB_ROUTING_PROTOCOL_GRE),
    (Protocol::IpIp, keys::WEB_ROUTING_PROTOCOL_IPIP),
    (Protocol::Ip, keys::WEB_ROUTING_PROTOCOL_IP),
];

/// The decision's label.
pub(crate) const fn action_label(action: Action) -> MessageKey {
    match action {
        Action::Deny => keys::WEB_FIREWALL_ACTION_DENY,
        Action::Permit | _ => keys::WEB_FIREWALL_ACTION_PERMIT,
    }
}

/// The protocol's label; `None` when the rule names none.
pub(crate) fn protocol_label(protocol: Option<Protocol>) -> Option<MessageKey> {
    let named = protocol?;
    PROTOCOLS
        .iter()
        .find(|(known, _)| *known == named)
        .map(|(_, label)| *label)
}

/// The side as people read it: the address alone for one host, `address/prefix`
/// otherwise; `None` for every address.
pub(crate) fn address_text(side: &Side) -> Option<String> {
    let bits = side
        .mask()
        .parse::<Ipv4Addr>()
        .ok()
        .map(|mask| u32::from(mask).count_ones())?;
    match bits {
        0 => None,
        32 => Some(side.address().to_owned()),
        prefix => Some(format!("{}/{prefix}", side.address())),
    }
}

#[cfg(test)]
#[path = "rule_tests.rs"]
mod tests;
