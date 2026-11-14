//! One access-list rule as the router stores it, and the structured form kcc reads from it.
//!
//! The documented form is `permit|deny <protocol> <source> <source-mask> [port eq
//! <port>] <destination> <destination-mask> [port eq <port>]` (CLI manual 3.3.3). kcc
//! also reads its own earlier form (no protocol, bare ports). A rule stored in any other
//! form (a port range, a port operator other than `eq`) keeps only its stored words.

use core::net::Ipv4Addr;

use super::model::{Action, Protocol, Rule};

/// Every decision, for reading a stored keyword.
const ACTIONS: [Action; 2] = [Action::Permit, Action::Deny];

/// Every protocol, for reading a stored keyword.
const PROTOCOLS: [Protocol; 7] = [
    Protocol::Tcp,
    Protocol::Udp,
    Protocol::Icmp,
    Protocol::Esp,
    Protocol::Gre,
    Protocol::IpIp,
    Protocol::Ip,
];

/// One side of a structured rule: an address, its mask and an exact port.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Side {
    /// Address.
    address: String,
    /// Mask.
    mask: String,
    /// Exact port, for TCP and UDP.
    port: Option<u16>,
}

impl Side {
    /// `address` with `mask` and `port`.
    #[inline]
    #[must_use]
    pub const fn new(address: String, mask: String, port: Option<u16>) -> Self {
        Self {
            address,
            mask,
            port,
        }
    }

    /// Address.
    #[inline]
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Mask.
    #[inline]
    #[must_use]
    pub fn mask(&self) -> &str {
        &self.mask
    }

    /// Exact port.
    #[inline]
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
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

/// A rule in the structured form: its decision, protocol and two sides.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RuleForm {
    /// Permit or deny.
    action: Action,
    /// Protocol; `None` in kcc's own earlier form.
    protocol: Option<Protocol>,
    /// Source side.
    source: Side,
    /// Destination side.
    destination: Side,
}

impl RuleForm {
    /// A rule from its parts.
    #[inline]
    #[must_use]
    pub const fn new(
        (action, protocol): (Action, Option<Protocol>),
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

    /// Reads a stored rule's words, when they are in the structured form.
    #[inline]
    #[must_use]
    pub fn read(words: &[String]) -> Option<Self> {
        let [first, rest @ ..] = words else {
            return None;
        };
        let action = ACTIONS.into_iter().find(|known| known.name() == first)?;
        let (protocol, sides) = match rest {
            [word, tail @ ..] => PROTOCOLS
                .into_iter()
                .find(|known| known.name() == word)
                .map_or((None, rest), |found| (Some(found), tail)),
            [] => (None, rest),
        };
        let (source, after_source) = Side::read(sides)?;
        let (destination, after) = Side::read(after_source)?;
        after
            .is_empty()
            .then(|| Self::new((action, protocol), source, destination))
    }

    /// The rule's words in the documented form.
    #[inline]
    #[must_use]
    pub fn words(&self) -> Vec<String> {
        let mut words = vec![self.action.name().to_owned()];
        words.extend(self.protocol.map(|protocol| protocol.name().to_owned()));
        words.extend(self.source.words());
        words.extend(self.destination.words());
        words
    }

    /// Permit or deny.
    #[inline]
    #[must_use]
    pub const fn action(&self) -> Action {
        self.action
    }

    /// Protocol; `None` when the rule names none.
    #[inline]
    #[must_use]
    pub const fn protocol(&self) -> Option<Protocol> {
        self.protocol
    }

    /// Source side.
    #[inline]
    #[must_use]
    pub const fn source(&self) -> &Side {
        &self.source
    }

    /// Destination side.
    #[inline]
    #[must_use]
    pub const fn destination(&self) -> &Side {
        &self.destination
    }

    /// The rule as the firewall planner takes it; a rule naming no protocol matches any IP
    /// protocol.
    #[inline]
    #[must_use]
    pub fn rule(&self) -> Rule {
        let mut rule = Rule::new(
            self.action,
            self.protocol.unwrap_or(Protocol::Ip),
            &self.source.address,
            &self.destination.address,
        );
        rule.source_mask.clone_from(&self.source.mask);
        rule.destination_mask.clone_from(&self.destination.mask);
        rule.source_port = self.source.port;
        rule.destination_port = self.destination.port;
        rule
    }
}

/// One stored rule: its words, and its structured form when it has one.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct StoredRule {
    /// The words after `access-list <name>`.
    words: Vec<String>,
    /// The structured form, when the words have one.
    form: Option<RuleForm>,
}

impl StoredRule {
    /// The stored rule of `words`.
    #[inline]
    #[must_use]
    pub fn new(words: Vec<String>) -> Self {
        let form = RuleForm::read(&words);
        Self { words, form }
    }

    /// The words after `access-list <name>`.
    #[inline]
    #[must_use]
    pub fn words(&self) -> &[String] {
        &self.words
    }

    /// The words as one line.
    #[inline]
    #[must_use]
    pub fn text(&self) -> String {
        self.words.join(" ")
    }

    /// The structured form, when the words have one.
    #[inline]
    #[must_use]
    pub const fn form(&self) -> Option<&RuleForm> {
        self.form.as_ref()
    }
}

#[cfg(test)]
#[path = "rule_words_tests.rs"]
mod tests;
