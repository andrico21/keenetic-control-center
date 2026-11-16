//! The static routes of the routing views, from `show ip route` and `show ipv6 route`: the
//! rows marked static, with the command they were added with, which the page can remove.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use kcc_domain::routing::model::{Ipv4Route, Ipv6Route, RouteTableEntry};
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_rci::ObjectName;

use crate::table::{
    Direction, Sort,
    rows::{Row, SortKey},
};

/// The address family of a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

impl Family {
    /// The `family` parameter value.
    pub(crate) const fn slug(self) -> &'static str {
        match self {
            Self::V4 => "ipv4",
            Self::V6 => "ipv6",
        }
    }

    /// The family a `family` parameter names; IPv4 when absent.
    pub(crate) fn from_slug(slug: Option<&str>) -> Option<Self> {
        match slug.unwrap_or("ipv4") {
            "ipv4" => Some(Self::V4),
            "ipv6" => Some(Self::V6),
            _ => None,
        }
    }

    /// The routing write of this family in the domain descriptor.
    pub(crate) const fn operation(self) -> &'static str {
        match self {
            Self::V4 => "ipv4_route",
            Self::V6 => "ipv6_route",
        }
    }

    /// The CLI command of this family's routes.
    pub(crate) const fn command(self) -> &'static str {
        match self {
            Self::V4 => "ip route",
            Self::V6 => "ipv6 route",
        }
    }

    /// The family's label.
    pub(crate) const fn label(self) -> MessageKey {
        match self {
            Self::V4 => keys::WEB_ROUTING_IPV4,
            Self::V6 => keys::WEB_ROUTING_IPV6,
        }
    }
}

/// One static route as the router stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaticRoute {
    /// Address family.
    family: Family,
    /// IPv4 network or IPv6 prefix.
    destination: String,
    /// IPv4 network mask.
    mask: Option<String>,
    /// Next hop.
    gateway: Option<String>,
    /// Egress interface.
    interface: Option<String>,
    /// Route metric.
    metric: Option<u32>,
}

impl StaticRoute {
    /// A route of `family` to `destination` (and `mask` for IPv4) through `gateway`
    /// and/or `interface`, with `metric`.
    pub(crate) fn new(
        family: Family,
        (destination, mask): (String, Option<String>),
        (gateway, interface): (Option<String>, Option<String>),
        metric: Option<u32>,
    ) -> Self {
        Self {
            family,
            destination,
            mask,
            gateway,
            interface,
            metric,
        }
    }

    /// The static route of a table row: rows marked static whose command has the shape
    /// the router stores (network, mask, gateway or interface, interface, metric).
    pub(crate) fn from_entry(family: Family, entry: &RouteTableEntry) -> Option<Self> {
        if entry.is_static != Some(true) {
            return None;
        }
        let words = entry.command.as_slice();
        let (destination, mask, rest) = match (family, words) {
            (Family::V4, [network, mask, rest @ ..]) => (network, Some(mask.clone()), rest),
            (Family::V6, [prefix, rest @ ..]) => (prefix, None, rest),
            (Family::V4 | Family::V6, _) => return None,
        };
        let (leading_gateway, after_gateway) = match rest {
            [first, tail @ ..] if first.parse::<IpAddr>().is_ok() => (Some(first.clone()), tail),
            _ => (None, rest),
        };
        let (interface, after_interface) = match after_gateway {
            [first, tail @ ..] if first.parse::<u32>().is_err() => (Some(first.clone()), tail),
            _ => (None, after_gateway),
        };
        // `ipv6 route <prefix> <interface> <gateway>`: the gateway follows the interface.
        let (gateway, tail) = match (family, leading_gateway, after_interface) {
            (Family::V6, None, [last]) if last.parse::<IpAddr>().is_ok() => {
                (Some(last.clone()), &[][..])
            }
            (_, found, remaining) => (found, remaining),
        };
        let metric = match (family, tail) {
            (_, []) => None,
            (Family::V4, [number]) => Some(number.parse::<u32>().ok()?),
            (Family::V4 | Family::V6, _) => return None,
        };
        (gateway.is_some() || interface.is_some()).then(|| {
            Self::new(
                family,
                (destination.clone(), mask),
                (gateway, interface),
                metric,
            )
        })
    }

    /// Address family.
    pub(crate) const fn family(&self) -> Family {
        self.family
    }

    /// The destination as people read it: `network/prefix` for a dotted mask.
    pub(crate) fn destination(&self) -> String {
        let bits = self
            .mask
            .as_deref()
            .and_then(|mask| mask.parse::<Ipv4Addr>().ok())
            .map(|mask| u32::from(mask).count_ones());
        match (bits, &self.mask) {
            (Some(prefix), _) => format!("{}/{prefix}", self.destination),
            (None, Some(mask)) => format!("{} {mask}", self.destination),
            (None, None) => self.destination.clone(),
        }
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
    pub(crate) const fn metric(&self) -> Option<u32> {
        self.metric
    }

    /// The command that adds the route, as the router stores it.
    pub(crate) fn stored(&self) -> String {
        let metric = self.metric.map(|value| value.to_string());
        let (first, second) = match self.family {
            Family::V4 => (self.gateway.as_deref(), self.interface.as_deref()),
            Family::V6 => (self.interface.as_deref(), self.gateway.as_deref()),
        };
        let words = [
            Some(self.destination.as_str()),
            self.mask.as_deref(),
            first,
            second,
            metric.as_deref(),
        ];
        let tail = words.into_iter().flatten().collect::<Vec<_>>().join(" ");
        format!("{} {tail}", self.family.command())
    }

    /// The query pairs naming the route in an action URL.
    pub(crate) fn pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = vec![
            ("family", self.family.slug().to_owned()),
            ("destination", self.destination.clone()),
        ];
        let optional = [
            ("mask", self.mask.clone()),
            ("gateway", self.gateway.clone()),
            ("interface", self.interface.clone()),
            ("metric", self.metric.map(|value| value.to_string())),
        ];
        pairs.extend(
            optional
                .into_iter()
                .filter_map(|(name, value)| value.map(|text| (name, text))),
        );
        pairs
    }

    /// The domain's IPv4 route, for planning.
    pub(crate) fn ipv4(&self) -> Ipv4Route {
        let mut route = Ipv4Route::network(
            &self.destination,
            self.mask.as_deref().unwrap_or_default(),
            "",
        );
        route.gateway.clone_from(&self.gateway);
        route.interface.clone_from(&self.interface);
        route.metric = self.metric;
        route
    }

    /// The domain's IPv6 route, for planning.
    pub(crate) fn ipv6(&self) -> Ipv6Route {
        let mut route = Ipv6Route::via_gateway(&self.destination, "");
        route.gateway.clone_from(&self.gateway);
        route.interface.clone_from(&self.interface);
        route
    }

    /// Whether every value is in its family's form: addresses, mask, interface name.
    pub(crate) fn well_formed(&self) -> bool {
        let address = |text: &str| match self.family {
            Family::V4 => text.parse::<Ipv4Addr>().is_ok(),
            Family::V6 => text.parse::<Ipv6Addr>().is_ok(),
        };
        let destination = match self.family {
            Family::V4 => address(&self.destination) && self.mask.as_deref().is_some_and(mask),
            Family::V6 => prefix(&self.destination) && self.mask.is_none(),
        };
        destination
            && self.gateway.as_deref().is_none_or(address)
            && self
                .interface
                .as_deref()
                .is_none_or(|name| name.parse::<ObjectName>().is_ok())
            && (self.gateway.is_some() || self.interface.is_some())
            && (self.family == Family::V4 || self.metric.is_none())
    }
}

/// Whether `text` is a contiguous dotted IPv4 mask.
pub(crate) fn mask(text: &str) -> bool {
    text.parse::<Ipv4Addr>().is_ok_and(|parsed| {
        let bits = u32::from(parsed);
        bits.leading_ones().saturating_add(bits.trailing_zeros()) == 32
    })
}

/// Whether `text` is an IPv6 prefix such as `2001:db8::/32`.
pub(crate) fn prefix(text: &str) -> bool {
    text.split_once('/').is_some_and(|(address, length)| {
        address.parse::<Ipv6Addr>().is_ok() && length.parse::<u8>().is_ok_and(|bits| bits <= 128)
    })
}

/// The sort key of an address: IPv4 by number, anything else as text.
pub(crate) fn address_key(text: &str) -> SortKey {
    let head = text.split(['/', ' ']).next().unwrap_or_default();
    head.parse::<Ipv4Addr>().map_or_else(
        |_| SortKey::text(text),
        |address| SortKey::Number(i128::from(u32::from(address))),
    )
}

/// The sort key of an optional text, missing last.
pub(crate) fn text_key(value: Option<&str>) -> SortKey {
    value.map_or(SortKey::Missing, SortKey::text)
}

impl Row for StaticRoute {
    const COLUMNS: &'static [&'static str] = &["destination", "gateway", "interface", "metric"];

    const DEFAULT: Sort = Sort::new("destination", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        match column {
            "gateway" => self.gateway().map_or(SortKey::Missing, address_key),
            "interface" => text_key(self.interface()),
            "metric" => self
                .metric
                .map_or(SortKey::Missing, |value| SortKey::Number(i128::from(value))),
            _ => address_key(&self.destination()),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        self.stored().to_lowercase().contains(needle)
            || self.destination().to_lowercase().contains(needle)
    }
}

/// The static routes of `entries`.
pub(crate) fn static_routes(family: Family, entries: &[RouteTableEntry]) -> Vec<StaticRoute> {
    entries
        .iter()
        .filter_map(|entry| StaticRoute::from_entry(family, entry))
        .collect()
}

#[cfg(test)]
#[path = "route_rows_tests.rs"]
mod tests;
