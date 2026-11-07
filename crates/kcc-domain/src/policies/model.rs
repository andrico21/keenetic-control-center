//! Typed connection-policy inputs and tolerant show rows.

use alloc::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One connection policy returned by `show ip policy`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct PolicyState {
    /// Policy name.
    pub name: Option<String>,
    /// Human-readable description.
    pub description: Option<String>,
    /// Whether global traffic is permitted by this policy.
    pub permit: Option<bool>,
    /// Whether equal-cost multipath routing is enabled.
    pub multipath: Option<bool>,
    /// Whether the policy operates independently.
    pub standalone: Option<bool>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// One permitted interface and its optional ordering weight.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PolicyPermit {
    /// Permitted interface.
    pub interface: String,
    /// Optional interface order.
    pub order: Option<u32>,
}

impl PolicyPermit {
    /// Creates a permitted interface.
    #[inline]
    #[must_use]
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_owned(),
            order: None,
        }
    }

    /// Sets the interface order.
    #[inline]
    #[must_use]
    pub const fn with_order(mut self, order: u32) -> Self {
        self.order = Some(order);
        self
    }
}

/// One IPv4 route owned by a connection policy.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PolicyRoute {
    /// Destination network or host.
    pub destination: String,
    /// Network mask, present for network routes.
    pub mask: Option<String>,
    /// Next-hop address.
    pub gateway: Option<String>,
    /// Egress interface.
    pub interface: Option<String>,
    /// Optional route metric.
    pub metric: Option<u32>,
}

impl PolicyRoute {
    /// Creates a network route through one interface.
    #[inline]
    #[must_use]
    pub fn network(network: &str, mask: &str, interface: &str) -> Self {
        Self {
            destination: network.to_owned(),
            mask: Some(mask.to_owned()),
            gateway: None,
            interface: Some(interface.to_owned()),
            metric: None,
        }
    }

    /// Creates a host route through one gateway.
    #[inline]
    #[must_use]
    pub fn host(host: &str, gateway: &str) -> Self {
        Self {
            destination: host.to_owned(),
            mask: None,
            gateway: Some(gateway.to_owned()),
            interface: None,
            metric: None,
        }
    }

    /// Sets the route metric.
    #[inline]
    #[must_use]
    pub const fn with_metric(mut self, metric: u32) -> Self {
        self.metric = Some(metric);
        self
    }
}

/// Rate-limit traffic direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RateDirection {
    /// Traffic entering the interface.
    Input,
    /// Traffic leaving the interface.
    Output,
}

impl RateDirection {
    /// Returns the catalog path suffix and CLI word.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Output => "output",
        }
    }
}

/// One interface rate limit.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PolicyRateLimit {
    /// Limited interface.
    pub interface: String,
    /// Traffic direction.
    pub direction: RateDirection,
    /// Explicit rate, or `None` for automatic selection.
    pub rate: Option<u32>,
}

impl PolicyRateLimit {
    /// Creates an automatic rate limit.
    #[inline]
    #[must_use]
    pub fn automatic(interface: &str, direction: RateDirection) -> Self {
        Self {
            interface: interface.to_owned(),
            direction,
            rate: None,
        }
    }

    /// Creates an explicit rate limit.
    #[inline]
    #[must_use]
    pub fn fixed(interface: &str, direction: RateDirection, rate: u32) -> Self {
        Self {
            interface: interface.to_owned(),
            direction,
            rate: Some(rate),
        }
    }
}
