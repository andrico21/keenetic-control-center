//! Typed NAT inputs and tolerant runtime rows.

use alloc::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Transport protocol accepted by a static forwarding rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Both TCP and UDP.
    TcpUdp,
    /// Internet Control Message Protocol.
    Icmp,
    /// Generic Routing Encapsulation.
    Gre,
    /// IP-in-IP.
    IpIp,
}

impl Protocol {
    /// Returns the catalog keyword.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::TcpUdp => "tcpudp",
            Self::Icmp => "icmp",
            Self::Gre => "gre",
            Self::IpIp => "ipip",
        }
    }
}

/// Destination selected by a static forwarding rule.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ForwardTarget {
    /// Internal IP address.
    Address(String),
    /// Registered host MAC address.
    Host(String),
}

/// One `ip static` forwarding rule.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PortForward {
    /// Optional transport protocol.
    pub protocol: Option<Protocol>,
    /// Incoming interface.
    pub interface: String,
    /// First external port.
    pub port: Option<u16>,
    /// Last external port for a range.
    pub end_port: Option<u16>,
    /// Forwarding destination.
    pub target: ForwardTarget,
    /// Optional translated port.
    pub to_port: Option<u16>,
}

impl PortForward {
    /// Creates a single-port address forwarding rule.
    #[inline]
    #[must_use]
    pub fn to_address(protocol: Protocol, interface: &str, port: u16, address: &str) -> Self {
        Self {
            protocol: Some(protocol),
            interface: interface.to_owned(),
            port: Some(port),
            end_port: None,
            target: ForwardTarget::Address(address.to_owned()),
            to_port: None,
        }
    }

    /// Sets the translated destination port.
    #[inline]
    #[must_use]
    pub const fn with_to_port(mut self, port: u16) -> Self {
        self.to_port = Some(port);
        self
    }
}

/// One configured command row returned by `show rc` or `show sc`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ConfiguredRule {
    /// Command tokens after the command path.
    pub command: Vec<String>,
    /// NAT-enabled interface when returned as a named field.
    pub interface: Option<String>,
}

/// One runtime NAT session row.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct NatSession {
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
}

/// One bounded server-side NAT page.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct NatPage {
    /// Zero-based row offset.
    pub offset: usize,
    /// Rows returned by the router.
    pub rows: Vec<NatSession>,
}
