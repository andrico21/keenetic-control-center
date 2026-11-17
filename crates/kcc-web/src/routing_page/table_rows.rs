//! The rows of the routing table, from `show ip route` and `show ipv6 route`: a static
//! route from the command it was added with, any other route from the router's fields.

use kcc_domain::routing::model::RouteTableEntry;

use super::route_rows::{Family, StaticRoute, address_key, text_key};
use crate::{
    net_change::scalar,
    table::{
        Direction, Sort,
        rows::{Row, SortKey},
    },
};

/// One row of the routing table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TableRoute {
    /// Destination network.
    destination: String,
    /// Next hop.
    gateway: Option<String>,
    /// Egress interface.
    interface: Option<String>,
    /// Route metric.
    metric: Option<String>,
    /// Whether the route is a static route.
    is_static: bool,
    /// Where the router says the route comes from, for a route that is not static.
    source: Option<String>,
}

impl TableRoute {
    /// The row of `entry`: a static route from its command, any other from its fields.
    pub(crate) fn from_entry(family: Family, entry: &RouteTableEntry) -> Option<Self> {
        if let Some(route) = StaticRoute::from_entry(family, entry) {
            return Some(Self {
                destination: route.destination(),
                gateway: route.gateway().map(str::to_owned),
                interface: route.interface().map(str::to_owned),
                metric: route.metric().map(|value| value.to_string()),
                is_static: true,
                source: None,
            });
        }
        let field = |name: &str| scalar(entry.extra.get(name));
        let destination = field("destination").or_else(|| field("network"))?;
        Some(Self {
            destination,
            gateway: field("gateway"),
            interface: field("interface"),
            metric: field("metric"),
            is_static: false,
            source: field("proto").or_else(|| field("flags")),
        })
    }

    /// Destination network.
    pub(crate) fn destination(&self) -> &str {
        &self.destination
    }

    /// Next hop.
    pub(crate) fn gateway(&self) -> Option<&str> {
        self.gateway.as_deref()
    }

    /// Egress interface.
    pub(crate) fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }

    /// Route metric.
    pub(crate) fn metric(&self) -> Option<&str> {
        self.metric.as_deref()
    }

    /// Where the router says the route comes from, for a route that is not static.
    pub(crate) fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Whether the route is a static route.
    pub(crate) const fn is_static(&self) -> bool {
        self.is_static
    }
}

impl Row for TableRoute {
    const COLUMNS: &'static [&'static str] =
        &["destination", "gateway", "interface", "metric", "source"];

    const DEFAULT: Sort = Sort::new("destination", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        match column {
            "gateway" => self.gateway().map_or(SortKey::Missing, address_key),
            "interface" => text_key(self.interface()),
            "metric" => self
                .metric()
                .and_then(|text| text.parse::<i128>().ok())
                .map_or(SortKey::Missing, SortKey::Number),
            "source" => text_key(self.source().or(Some(""))),
            _ => address_key(&self.destination),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        [
            Some(self.destination.as_str()),
            self.gateway(),
            self.interface(),
            self.metric(),
            self.source(),
        ]
        .into_iter()
        .flatten()
        .any(|text| text.to_lowercase().contains(needle))
    }
}

/// The routing-table rows of `entries`.
pub(crate) fn table_routes(family: Family, entries: &[RouteTableEntry]) -> Vec<TableRoute> {
    entries
        .iter()
        .filter_map(|entry| TableRoute::from_entry(family, entry))
        .collect()
}
