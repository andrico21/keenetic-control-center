//! The rows of the DHCP views: pools, and the hosts of the static leases, active leases
//! and ARP table, named after the clients the router reports.

use alloc::collections::BTreeMap;
use core::{net::Ipv4Addr, str::FromStr as _};

use fluent_bundle::FluentArgs;
use kcc_domain::{
    clients::Client,
    dhcp::model::{Binding, Neighbour, Pool, StaticLease},
};
use kcc_i18n::{bundle::tr, format, keys, locale::Locale};

use crate::table::{
    Direction, Sort,
    rows::{Row, SortKey},
};

/// Client names by lowercase MAC address.
pub(crate) type Names = BTreeMap<String, String>;

/// The names of `clients` by lowercase MAC address.
pub(crate) fn names(clients: Vec<Client>) -> Names {
    clients
        .into_iter()
        .filter_map(|client| {
            let name = client.name.filter(|name| !name.is_empty())?;
            Some((client.mac?.to_lowercase(), name))
        })
        .collect()
}

/// An address that sorts by value: IPv4 numerically, anything else as text.
fn address_key(address: Option<&str>) -> SortKey {
    address.map_or(SortKey::Missing, |text| {
        Ipv4Addr::from_str(text).map_or_else(
            |_| SortKey::text(text),
            |ip| SortKey::Number(u32::from(ip).into()),
        )
    })
}

/// Text that sorts without regard to case, or missing.
fn text_key(value: Option<&str>) -> SortKey {
    value.map_or(SortKey::Missing, SortKey::text)
}

/// One DHCP pool as the pools view shows it.
#[derive(Debug, Clone)]
pub(crate) struct PoolRow {
    /// Pool name, the row's identity.
    name: String,
    /// First allocatable address.
    begin: Option<String>,
    /// The range, localized.
    range: Option<String>,
    /// Advertised default gateway.
    gateway: Option<String>,
    /// Advertised DNS servers, joined.
    dns: Option<String>,
    /// Lease time in seconds.
    lease: Option<u64>,
    /// Lease time, localized.
    lease_text: Option<String>,
    /// Bound interface.
    interface: Option<String>,
    /// Whether the pool hands out addresses.
    enabled: bool,
}

impl PoolRow {
    /// The row of `pool` in `locale`; `None` for a pool without a name.
    pub(crate) fn new(pool: Pool, locale: Locale) -> Option<Self> {
        let range = pool
            .range_begin
            .as_deref()
            .zip(pool.range_end.as_deref())
            .map(|(begin, end)| {
                let mut args = FluentArgs::new();
                args.set("first", begin.to_owned());
                args.set("last", end.to_owned());
                tr(locale, keys::WEB_DHCP_RANGE_VALUE, Some(&args))
            });
        Some(Self {
            name: pool.name.filter(|name| !name.is_empty())?,
            begin: pool.range_begin,
            range,
            gateway: pool.default_router,
            dns: (!pool.dns_servers.is_empty()).then(|| pool.dns_servers.join(", ")),
            lease: pool.lease,
            lease_text: pool.lease.map(|seconds| format::duration(locale, seconds)),
            interface: pool.interface,
            enabled: pool.enabled == Some(true),
        })
    }

    /// Pool name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The range, localized.
    pub(crate) fn range(&self) -> Option<&str> {
        self.range.as_deref()
    }

    /// Advertised default gateway.
    pub(crate) fn gateway(&self) -> Option<&str> {
        self.gateway.as_deref()
    }

    /// Advertised DNS servers.
    pub(crate) fn dns(&self) -> Option<&str> {
        self.dns.as_deref()
    }

    /// Lease time, localized.
    pub(crate) fn lease(&self) -> Option<&str> {
        self.lease_text.as_deref()
    }

    /// Bound interface.
    pub(crate) fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }

    /// Whether the pool hands out addresses.
    pub(crate) const fn enabled(&self) -> bool {
        self.enabled
    }
}

impl Row for PoolRow {
    const COLUMNS: &'static [&'static str] = &[
        "name",
        "range",
        "gateway",
        "dns",
        "lease",
        "interface",
        "state",
    ];
    const DEFAULT: Sort = Sort::new("name", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        match column {
            "range" => address_key(self.begin.as_deref()),
            "gateway" => address_key(self.gateway.as_deref()),
            "dns" => text_key(self.dns.as_deref()),
            "lease" => self
                .lease
                .map_or(SortKey::Missing, |seconds| SortKey::Number(seconds.into())),
            "interface" => text_key(self.interface.as_deref()),
            "state" => SortKey::Number(i128::from(u8::from(!self.enabled))),
            _ => SortKey::text(&self.name),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        [
            Some(self.name.as_str()),
            self.interface.as_deref(),
            self.range.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| value.to_lowercase().contains(needle))
    }
}

/// A host of the static leases, active leases or ARP views.
#[derive(Debug, Clone)]
pub(crate) struct HostRow {
    /// MAC address, the row's identity.
    mac: String,
    /// IPv4 address.
    address: Option<String>,
    /// The client's name, when the router reports one.
    device: Option<String>,
    /// Interface the host was seen on.
    interface: Option<String>,
    /// Binding or reachability state.
    state: Option<String>,
    /// Seconds until the lease expires.
    expires: Option<u64>,
    /// The remaining lease time, localized.
    expires_text: Option<String>,
}

impl HostRow {
    /// A host from its MAC and address, named from `names`.
    fn named(reported: Option<String>, address: Option<String>, names: &Names) -> Option<Self> {
        let mac = reported.filter(|text| !text.is_empty())?;
        Some(Self {
            device: names.get(&mac.to_lowercase()).cloned(),
            mac,
            address,
            interface: None,
            state: None,
            expires: None,
            expires_text: None,
        })
    }

    /// The row of a static lease.
    pub(crate) fn lease(lease: StaticLease, names: &Names) -> Option<Self> {
        Self::named(lease.mac, lease.address, names)
    }

    /// The row of an active lease in `locale`.
    pub(crate) fn binding(binding: Binding, names: &Names, locale: Locale) -> Option<Self> {
        Some(Self {
            interface: binding.interface,
            state: binding.state,
            expires: binding.expires,
            expires_text: binding
                .expires
                .map(|seconds| format::duration(locale, seconds)),
            ..Self::named(binding.mac, binding.address, names)?
        })
    }

    /// The row of an ARP neighbour.
    pub(crate) fn neighbour(neighbour: Neighbour, names: &Names) -> Option<Self> {
        Some(Self {
            interface: neighbour.interface,
            state: neighbour.state,
            ..Self::named(neighbour.mac, neighbour.address, names)?
        })
    }

    /// MAC address.
    pub(crate) fn mac(&self) -> &str {
        &self.mac
    }

    /// IPv4 address.
    pub(crate) fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    /// The client's name.
    pub(crate) fn device(&self) -> Option<&str> {
        self.device.as_deref()
    }

    /// Interface the host was seen on.
    pub(crate) fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }

    /// Binding or reachability state.
    pub(crate) fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    /// The remaining lease time, localized.
    pub(crate) fn expires(&self) -> Option<&str> {
        self.expires_text.as_deref()
    }
}

impl Row for HostRow {
    const COLUMNS: &'static [&'static str] =
        &["device", "mac", "address", "interface", "state", "expires"];
    const DEFAULT: Sort = Sort::new("address", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        match column {
            "device" => text_key(self.device.as_deref()),
            "mac" => SortKey::text(&self.mac),
            "interface" => text_key(self.interface.as_deref()),
            "state" => text_key(self.state.as_deref()),
            "expires" => self
                .expires
                .map_or(SortKey::Missing, |seconds| SortKey::Number(seconds.into())),
            _ => address_key(self.address.as_deref()),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        [
            Some(self.mac.as_str()),
            self.address.as_deref(),
            self.device.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| value.to_lowercase().contains(needle))
    }
}
