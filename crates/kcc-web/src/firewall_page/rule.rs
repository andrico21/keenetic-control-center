//! One firewall rule as the router stores it in an access list, and what the page shows
//! of it.
//!
//! The documented form is `permit|deny <protocol> <source> <source-mask> [port eq
//! <port>] <destination> <destination-mask> [port eq <port>]` (CLI manual 3.3.3). Rules
//! stored in that form, or in the firewall domain's own form (no protocol, bare ports),
//! can be removed and moved; any other form is shown as stored and changed in the command
//! explorer.

use core::net::Ipv4Addr;

use kcc_domain::firewall::model::{Action, Protocol, Rule};
use kcc_i18n::{bundle::MessageKey, keys};

/// The protocols a rule may name, as the router spells them, with their labels.
pub(crate) const PROTOCOLS: [(&str, MessageKey); 7] = [
    ("tcp", keys::WEB_ROUTING_PROTOCOL_TCP),
    ("udp", keys::WEB_ROUTING_PROTOCOL_UDP),
    ("icmp", keys::WEB_ROUTING_PROTOCOL_ICMP),
    ("esp", keys::WEB_ROUTING_PROTOCOL_ESP),
    ("gre", keys::WEB_ROUTING_PROTOCOL_GRE),
    ("ipip", keys::WEB_ROUTING_PROTOCOL_IPIP),
    ("ip", keys::WEB_ROUTING_PROTOCOL_IP),
];

/// One side of a rule: an address, its mask and an exact port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Side {
    /// Address.
    address: String,
    /// Mask.
    mask: String,
    /// Exact port, for TCP and UDP.
    port: Option<u16>,
}

impl Side {
    /// `address` with `mask` and `port`.
    pub(crate) const fn new(address: String, mask: String, port: Option<u16>) -> Self {
        Self {
            address,
            mask,
            port,
        }
    }

    /// The side as people read it: the address alone for one host, `address/prefix`
    /// otherwise; `None` for every address.
    pub(crate) fn address_text(&self) -> Option<String> {
        let bits = self
            .mask
            .parse::<Ipv4Addr>()
            .ok()
            .map(|mask| u32::from(mask).count_ones())?;
        match bits {
            0 => None,
            32 => Some(self.address.clone()),
            prefix => Some(format!("{}/{prefix}", self.address)),
        }
    }

    /// Exact port.
    pub(crate) const fn port(&self) -> Option<u16> {
        self.port
    }

    /// The side's words in the documented form.
    fn words(&self) -> Vec<String> {
        let mut words = vec![self.address.clone(), self.mask.clone()];
        if let Some(port) = self.port {
            words.extend(["port".to_owned(), "eq".to_owned(), port.to_string()]);
        }
        words
    }

    /// Reads one side from the start of `words`, with its port in the documented form or
    /// bare; returns the side and the words after it.
    fn read(words: &[String]) -> Option<(Self, &[String])> {
        let [address, mask, rest @ ..] = words else {
            return None;
        };
        if address.parse::<Ipv4Addr>().is_err() || mask.parse::<Ipv4Addr>().is_err() {
            return None;
        }
        let (port, after) = match rest {
            [keyword, operator, number, tail @ ..] if keyword == "port" && operator == "eq" => {
                (Some(number.parse().ok()?), tail)
            }
            [keyword, ..] if keyword == "port" => return None,
            [number, tail @ ..] if number.parse::<u16>().is_ok() => (number.parse().ok(), tail),
            _ => (None, rest),
        };
        Some((Self::new(address.clone(), mask.clone(), port), after))
    }
}

/// A rule the page can change: its decision, protocol and two sides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Parsed {
    /// `permit` or `deny`.
    action: String,
    /// Protocol keyword; `None` in the domain's own form.
    protocol: Option<String>,
    /// Source side.
    source: Side,
    /// Destination side.
    destination: Side,
}

impl Parsed {
    /// A rule from its parts.
    pub(crate) fn new(
        (action, protocol): (String, Option<String>),
        source: Side,
        destination: Side,
    ) -> Self {
        Self {
            action,
            protocol,
            source,
            destination,
        }
    }

    /// Reads a stored rule's words, when they have a form the page can change.
    pub(crate) fn read(words: &[String]) -> Option<Self> {
        let [action, rest @ ..] = words else {
            return None;
        };
        if action != "permit" && action != "deny" {
            return None;
        }
        let (protocol, sides) = match rest {
            [first, tail @ ..] if PROTOCOLS.iter().any(|(name, _)| name == first) => {
                (Some(first.clone()), tail)
            }
            _ => (None, rest),
        };
        let (source, after_source) = Side::read(sides)?;
        let (destination, after) = Side::read(after_source)?;
        after
            .is_empty()
            .then(|| Self::new((action.clone(), protocol), source, destination))
    }

    /// The rule's words in the documented form.
    pub(crate) fn words(&self) -> Vec<String> {
        let mut words = vec![self.action.clone()];
        words.extend(self.protocol.clone());
        words.extend(self.source.words());
        words.extend(self.destination.words());
        words
    }

    /// The decision's label.
    pub(crate) fn action_label(&self) -> MessageKey {
        if self.action == "deny" {
            keys::WEB_FIREWALL_ACTION_DENY
        } else {
            keys::WEB_FIREWALL_ACTION_PERMIT
        }
    }

    /// The protocol's label; `None` when the rule names none.
    pub(crate) fn protocol_label(&self) -> Option<MessageKey> {
        let name = self.protocol.as_deref()?;
        PROTOCOLS
            .iter()
            .find(|(known, _)| *known == name)
            .map(|(_, label)| *label)
    }

    /// Source side.
    pub(crate) const fn source(&self) -> &Side {
        &self.source
    }

    /// Destination side.
    pub(crate) const fn destination(&self) -> &Side {
        &self.destination
    }

    /// The firewall domain's rule, for catalog validation of the addresses, masks and
    /// ports.
    pub(crate) fn domain(&self) -> Rule {
        let action = if self.action == "deny" {
            Action::Deny
        } else {
            Action::Permit
        };
        let protocol = match self.protocol.as_deref() {
            Some("tcp") => Protocol::Tcp,
            Some("udp") => Protocol::Udp,
            Some("icmp") => Protocol::Icmp,
            Some("esp") => Protocol::Esp,
            Some("gre") => Protocol::Gre,
            Some("ipip") => Protocol::IpIp,
            Some(_) | None => Protocol::Ip,
        };
        let mut rule = Rule::new(
            action,
            protocol,
            &self.source.address,
            &self.destination.address,
        );
        rule.source_mask.clone_from(&self.source.mask);
        rule.destination_mask.clone_from(&self.destination.mask);
        rule.source_port = self.source.port;
        rule.source_end_port = None;
        rule.destination_port = self.destination.port;
        rule.destination_end_port = None;
        rule
    }
}

/// One stored rule: its words, and the rule the page can change when it has such a form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredRule {
    /// The words after `access-list <name>`.
    words: Vec<String>,
    /// The rule, when the page can change it.
    parsed: Option<Parsed>,
}

impl StoredRule {
    /// The stored rule of `words`.
    pub(crate) fn new(words: Vec<String>) -> Self {
        let parsed = Parsed::read(&words);
        Self { words, parsed }
    }

    /// The words after `access-list <name>`.
    pub(crate) fn words(&self) -> &[String] {
        &self.words
    }

    /// The words as one line.
    pub(crate) fn text(&self) -> String {
        self.words.join(" ")
    }

    /// The rule, when the page can change it.
    pub(crate) const fn parsed(&self) -> Option<&Parsed> {
        self.parsed.as_ref()
    }
}

#[cfg(test)]
#[path = "rule_tests.rs"]
mod tests;
