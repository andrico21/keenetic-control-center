//! The port forwarding rules of the NAT page, from the configured `ip static` lines.
//!
//! A rule names its protocol (or none for every protocol), the incoming interface, the
//! external port or range (or none for every port), the device it forwards to and the
//! port there. Rules in a form the NAT domain cannot express (an address and mask instead
//! of an interface, an interface as the target) are listed, not changed here.

use core::{net::Ipv4Addr, str::FromStr as _};

use kcc_domain::nat::model::{ConfiguredRule, ForwardTarget, PortForward, Protocol};
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_rci::Mac;

use crate::table::{
    Direction, Sort,
    rows::{Row, SortKey},
};

/// The protocols a rule may name, as the router spells them, with their labels.
pub(crate) const PROTOCOLS: [(&str, MessageKey); 6] = [
    ("tcp", keys::WEB_ROUTING_PROTOCOL_TCP),
    ("udp", keys::WEB_ROUTING_PROTOCOL_UDP),
    ("tcpudp", keys::WEB_ROUTING_PROTOCOL_TCPUDP),
    ("icmp", keys::WEB_ROUTING_PROTOCOL_ICMP),
    ("gre", keys::WEB_ROUTING_PROTOCOL_GRE),
    ("ipip", keys::WEB_ROUTING_PROTOCOL_IPIP),
];

/// Whether `protocol` carries ports: none (every protocol), TCP, UDP or both.
pub(crate) fn has_ports(protocol: Option<&str>) -> bool {
    protocol.is_none_or(|name| matches!(name, "tcp" | "udp" | "tcpudp"))
}

/// One port forwarding rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Forward {
    /// Protocol keyword; `None` for every protocol.
    protocol: Option<String>,
    /// Incoming interface, or an address and mask.
    incoming: String,
    /// Whether `incoming` is an interface the NAT domain can name.
    by_interface: bool,
    /// First external port.
    port: Option<u16>,
    /// Last external port of a range.
    end_port: Option<u16>,
    /// The address, MAC address or interface forwarded to.
    target: String,
    /// Port on the target.
    to_port: Option<u16>,
}

impl Forward {
    /// A rule from its parts, as the Add dialog or an action URL names it.
    pub(crate) fn new(
        (protocol, incoming): (Option<String>, String),
        (port, end_port): (Option<u16>, Option<u16>),
        (target, to_port): (String, Option<u16>),
    ) -> Self {
        Self {
            protocol,
            incoming,
            by_interface: true,
            port,
            end_port,
            target,
            to_port,
        }
    }

    /// The rule of a configured `ip static` line, when its words have the router's form.
    pub(crate) fn from_rule(rule: &ConfiguredRule) -> Option<Self> {
        let words = rule.command.as_slice();
        let (protocol, rest) = match words {
            [first, tail @ ..] if PROTOCOLS.iter().any(|(name, _)| name == first) => {
                (Some(first.clone()), tail)
            }
            _ => (None, words),
        };
        let (incoming, by_interface, after_incoming) = match rest {
            [address, mask, tail @ ..]
                if address.parse::<Ipv4Addr>().is_ok() && mask.parse::<Ipv4Addr>().is_ok() =>
            {
                (format!("{address} {mask}"), false, tail)
            }
            [interface, tail @ ..] => (interface.clone(), true, tail),
            [] => return None,
        };
        let (port, end_port, target, to_port) = match after_incoming {
            [port, through, end, target] if through == "through" => (
                Some(port.parse().ok()?),
                Some(end.parse().ok()?),
                target,
                None,
            ),
            [port, target, to_port] => (
                Some(port.parse().ok()?),
                None,
                target,
                Some(to_port.parse().ok()?),
            ),
            [port, target] if port.parse::<u16>().is_ok() => {
                (Some(port.parse().ok()?), None, target, None)
            }
            [target] => (None, None, target, None),
            _ => return None,
        };
        Some(Self {
            protocol,
            incoming,
            by_interface,
            port,
            end_port,
            target: target.clone(),
            to_port,
        })
    }

    /// The protocol's label; `None` for every protocol.
    pub(crate) fn protocol_label(&self) -> Option<MessageKey> {
        let name = self.protocol.as_deref()?;
        PROTOCOLS
            .iter()
            .find(|(known, _)| *known == name)
            .map(|(_, label)| *label)
    }

    /// Incoming interface, or address and mask.
    pub(crate) fn incoming(&self) -> &str {
        &self.incoming
    }

    /// The external ports: `(first, last)` of a range, `(first, None)` for one port.
    pub(crate) const fn ports(&self) -> Option<(u16, Option<u16>)> {
        match self.port {
            Some(first) => Some((first, self.end_port)),
            None => None,
        }
    }

    /// The device forwarded to.
    pub(crate) fn target(&self) -> &str {
        &self.target
    }

    /// The port on the target.
    pub(crate) const fn to_port(&self) -> Option<u16> {
        self.to_port
    }

    /// The domain's rule, when the NAT domain can express this one.
    pub(crate) fn domain_rule(&self) -> Option<PortForward> {
        if !self.by_interface {
            return None;
        }
        let target = if self.target.parse::<Ipv4Addr>().is_ok() {
            ForwardTarget::Address(self.target.clone())
        } else if Mac::from_str(&self.target).is_ok() {
            ForwardTarget::Host(self.target.clone())
        } else {
            return None;
        };
        let protocol = match self.protocol.as_deref() {
            None => None,
            Some("tcp") => Some(Protocol::Tcp),
            Some("udp") => Some(Protocol::Udp),
            Some("tcpudp") => Some(Protocol::TcpUdp),
            Some("icmp") => Some(Protocol::Icmp),
            Some("gre") => Some(Protocol::Gre),
            Some("ipip") => Some(Protocol::IpIp),
            Some(_) => return None,
        };
        let mut rule = PortForward::to_address(Protocol::Tcp, &self.incoming, 0, "");
        rule.protocol = protocol;
        rule.port = self.port;
        rule.end_port = self.end_port;
        rule.target = target;
        rule.to_port = self.to_port;
        Some(rule)
    }

    /// The query pairs naming the rule in an action URL.
    pub(crate) fn pairs(&self) -> Vec<(&'static str, String)> {
        let optional = [
            ("protocol", self.protocol.clone()),
            ("port", self.port.map(|port| port.to_string())),
            ("end", self.end_port.map(|port| port.to_string())),
            ("to", self.to_port.map(|port| port.to_string())),
        ];
        let mut pairs = vec![
            ("interface", self.incoming.clone()),
            ("target", self.target.clone()),
        ];
        pairs.extend(
            optional
                .into_iter()
                .filter_map(|(name, value)| value.map(|text| (name, text))),
        );
        pairs
    }
}

/// The sort key of an optional port, missing first.
fn port_key(port: Option<u16>) -> SortKey {
    port.map_or(SortKey::Number(-1), |found| {
        SortKey::Number(i128::from(found))
    })
}

impl Row for Forward {
    const COLUMNS: &'static [&'static str] =
        &["protocol", "interface", "ports", "target", "target_port"];

    const DEFAULT: Sort = Sort::new("ports", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        match column {
            "protocol" => SortKey::text(self.protocol.as_deref().unwrap_or_default()),
            "interface" => SortKey::text(&self.incoming),
            "target" => self.target.parse::<Ipv4Addr>().map_or_else(
                |_| SortKey::text(&self.target),
                |address| SortKey::Number(i128::from(u32::from(address))),
            ),
            "target_port" => port_key(self.to_port),
            _ => port_key(self.port),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        let ports = [self.port, self.end_port, self.to_port]
            .into_iter()
            .flatten()
            .map(|port| port.to_string());
        [
            self.protocol.clone().unwrap_or_default(),
            self.incoming.to_lowercase(),
            self.target.to_lowercase(),
        ]
        .into_iter()
        .chain(ports)
        .any(|text| text.contains(needle))
    }
}

/// The rules of the configured `ip static` lines that have the router's form.
pub(crate) fn forwards(rules: &[ConfiguredRule]) -> Vec<Forward> {
    rules.iter().filter_map(Forward::from_rule).collect()
}

#[cfg(test)]
#[path = "forwards_tests.rs"]
mod tests;
