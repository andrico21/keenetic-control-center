//! Typed route inputs and tolerant routing-table rows.

use alloc::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One configured IPv4 static route.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Ipv4Route {
    /// Destination network address, host address, or `default`.
    pub destination: String,
    /// Network mask, present only for network routes.
    pub mask: Option<String>,
    /// Next-hop address.
    pub gateway: Option<String>,
    /// Egress interface.
    pub interface: Option<String>,
    /// Optional route metric.
    pub metric: Option<u32>,
}

impl Ipv4Route {
    /// Creates a network route through one gateway.
    #[inline]
    #[must_use]
    pub fn network(network: &str, mask: &str, gateway: &str) -> Self {
        Self {
            destination: network.to_owned(),
            mask: Some(mask.to_owned()),
            gateway: Some(gateway.to_owned()),
            interface: None,
            metric: None,
        }
    }

    /// Sets the egress interface.
    #[inline]
    #[must_use]
    pub fn on_interface(mut self, interface: &str) -> Self {
        self.interface = Some(interface.to_owned());
        self
    }

    /// Sets the route metric.
    #[inline]
    #[must_use]
    pub const fn with_metric(mut self, metric: u32) -> Self {
        self.metric = Some(metric);
        self
    }
}

/// One configured IPv6 static route.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Ipv6Route {
    /// Destination prefix or `default`.
    pub prefix: String,
    /// Next-hop address.
    pub gateway: Option<String>,
    /// Egress interface.
    pub interface: Option<String>,
}

impl Ipv6Route {
    /// Creates a route through one gateway.
    #[inline]
    #[must_use]
    pub fn via_gateway(prefix: &str, gateway: &str) -> Self {
        Self {
            prefix: prefix.to_owned(),
            gateway: Some(gateway.to_owned()),
            interface: None,
        }
    }

    /// Sets the egress interface.
    #[inline]
    #[must_use]
    pub fn on_interface(mut self, interface: &str) -> Self {
        self.interface = Some(interface.to_owned());
        self
    }
}

/// Tolerant routing-table row.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct RouteTableEntry {
    /// Whether this row represents a configured static route.
    #[serde(rename = "static")]
    pub is_static: Option<bool>,
    /// Command arguments when exposed by the router.
    pub command: Vec<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
