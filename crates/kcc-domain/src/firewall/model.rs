//! Typed firewall inputs and tolerant read models.

use alloc::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Firewall decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Action {
    /// Accept matching traffic.
    Permit,
    /// Reject matching traffic.
    Deny,
}

impl Action {
    /// Returns the CLI and catalog suffix.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Permit => "permit",
            Self::Deny => "deny",
        }
    }
}

/// Firewall protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP.
    Icmp,
    /// Encapsulating Security Payload.
    Esp,
    /// Generic Routing Encapsulation.
    Gre,
    /// IP-in-IP.
    IpIp,
    /// Any IP protocol.
    Ip,
}

impl Protocol {
    /// Returns the CLI keyword.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Esp => "esp",
            Self::Gre => "gre",
            Self::IpIp => "ipip",
            Self::Ip => "ip",
        }
    }
}

/// One IPv4 access-list rule.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Rule {
    /// Permit or deny decision.
    pub action: Action,
    /// Matched protocol.
    pub protocol: Protocol,
    /// Source address.
    pub source: String,
    /// Source network mask.
    pub source_mask: String,
    /// Destination address.
    pub destination: String,
    /// Destination network mask.
    pub destination_mask: String,
    /// Optional exact source port.
    pub source_port: Option<u16>,
    /// Optional exact destination port.
    pub destination_port: Option<u16>,
}

impl Rule {
    /// Creates a rule without port constraints.
    #[inline]
    #[must_use]
    pub fn new(action: Action, protocol: Protocol, source: &str, destination: &str) -> Self {
        Self {
            action,
            protocol,
            source: source.to_owned(),
            source_mask: "255.255.255.255".to_owned(),
            destination: destination.to_owned(),
            destination_mask: "255.255.255.255".to_owned(),
            source_port: None,
            destination_port: None,
        }
    }

    /// Constrains the source port.
    #[inline]
    #[must_use]
    pub const fn with_source_port(mut self, port: u16) -> Self {
        self.source_port = Some(port);
        self
    }

    /// Constrains the destination port.
    #[inline]
    #[must_use]
    pub const fn with_destination_port(mut self, port: u16) -> Self {
        self.destination_port = Some(port);
        self
    }
}

/// Access-list binding direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Direction {
    /// Inbound traffic.
    In,
    /// Outbound traffic.
    Out,
}

impl Direction {
    /// Returns the catalog keyword.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::In => "in",
            Self::Out => "out",
        }
    }
}

/// One UPnP-created redirect.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct UpnpRedirect {
    /// Transport protocol.
    pub protocol: Option<String>,
    /// Public port.
    #[serde(rename = "external-port")]
    pub external_port: Option<u16>,
    /// Internal destination address.
    #[serde(rename = "internal-address")]
    pub internal_address: Option<String>,
    /// Internal destination port.
    #[serde(rename = "internal-port")]
    pub internal_port: Option<u16>,
    /// Client-provided description.
    pub description: Option<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
