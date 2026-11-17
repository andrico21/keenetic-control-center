//! Typed DHCP boundary models and running-configuration pool parsing.

use alloc::collections::BTreeMap;
use core::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Tolerant DHCP pool model reconstructed from running configuration.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Pool {
    /// Pool name.
    pub name: Option<String>,
    /// First allocatable address.
    pub range_begin: Option<String>,
    /// Last allocatable address.
    pub range_end: Option<String>,
    /// Advertised default router.
    pub default_router: Option<String>,
    /// Advertised DNS servers.
    pub dns_servers: Vec<String>,
    /// Lease duration in seconds.
    pub lease: Option<u64>,
    /// Interface bound to this pool.
    pub interface: Option<String>,
    /// Whether this pool is enabled.
    pub enabled: Option<bool>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Tolerant static DHCP lease.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct StaticLease {
    /// Client MAC address.
    pub mac: Option<String>,
    /// Reserved address.
    #[serde(alias = "ip")]
    pub address: Option<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Tolerant dynamic DHCP binding.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Binding {
    /// Client MAC address.
    pub mac: Option<String>,
    /// Bound address.
    #[serde(alias = "ip")]
    pub address: Option<String>,
    /// Bound interface.
    pub interface: Option<String>,
    /// Binding state.
    pub state: Option<String>,
    /// Remaining lease seconds.
    pub expires: Option<u64>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Tolerant ARP neighbour row.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Neighbour {
    /// Neighbour MAC address.
    pub mac: Option<String>,
    /// Neighbour address.
    #[serde(alias = "ip")]
    pub address: Option<String>,
    /// Observing interface.
    pub interface: Option<String>,
    /// Reachability state.
    pub state: Option<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// One complete DHCP pool configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PoolConfig {
    /// Pool name.
    pub name: String,
    /// First allocatable address.
    pub range_begin: Ipv4Addr,
    /// Last allocatable address.
    pub range_end: Ipv4Addr,
    /// Advertised default router.
    pub default_router: Ipv4Addr,
    /// Advertised DNS server: `None` leaves the pool's DNS servers as they are, an empty
    /// list removes them, one address sets it; more than one is refused when planned.
    pub dns_servers: Option<Vec<Ipv4Addr>>,
    /// Lease duration in seconds.
    pub lease_seconds: u64,
    /// Interface bound to this pool.
    pub interface: String,
    /// Whether this pool is enabled.
    pub enabled: bool,
}

impl PoolConfig {
    /// Creates a disabled pool with an empty interface that leaves the DNS servers as they
    /// are.
    #[inline]
    #[must_use]
    pub const fn new(name: String, range_begin: Ipv4Addr, range_end: Ipv4Addr) -> Self {
        Self {
            name,
            range_begin,
            range_end,
            default_router: range_begin,
            dns_servers: None,
            lease_seconds: 86_400,
            interface: String::new(),
            enabled: false,
        }
    }

    /// Sets the advertised default router.
    #[inline]
    #[must_use]
    pub const fn with_default_router(mut self, address: Ipv4Addr) -> Self {
        self.default_router = address;
        self
    }

    /// Sets the advertised DNS servers; an empty list removes them.
    #[inline]
    #[must_use]
    pub fn with_dns_servers(mut self, addresses: Vec<Ipv4Addr>) -> Self {
        self.dns_servers = Some(addresses);
        self
    }

    /// Sets the lease duration in seconds.
    #[inline]
    #[must_use]
    pub const fn with_lease_seconds(mut self, seconds: u64) -> Self {
        self.lease_seconds = seconds;
        self
    }

    /// Binds the pool to an interface.
    #[inline]
    #[must_use]
    pub fn with_interface(mut self, interface: String) -> Self {
        self.interface = interface;
        self
    }

    /// Sets whether the pool is enabled.
    #[inline]
    #[must_use]
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// Parses pool contexts from canonical running configuration text: a pool is its
/// `ip dhcp pool` header and the indented lines under it, up to the next top-level line.
pub(super) fn parse_pools(text: &str) -> Vec<Pool> {
    let mut pools = Vec::<Pool>::new();
    let mut inside_pool = false;
    for line in text.lines() {
        let words = line.split_whitespace().collect::<Vec<_>>();
        let indented = line.starts_with(char::is_whitespace);
        match words.as_slice() {
            ["ip", "dhcp", "pool", name] => {
                pools.push(Pool {
                    name: Some((*name).to_owned()),
                    ..Pool::default()
                });
                inside_pool = true;
            }
            [
                field @ ("range" | "default-router" | "dns-server" | "lease" | "bind" | "enable"),
                rest @ ..,
            ] if indented && inside_pool => {
                if let Some(pool) = pools.last_mut() {
                    apply_pool_field(pool, field, rest);
                }
            }
            _ if !indented => inside_pool = false,
            _ => {}
        }
    }
    pools
}

/// Applies one parsed pool child line.
fn apply_pool_field(pool: &mut Pool, field: &str, values: &[&str]) {
    match (field, values) {
        ("range", [begin, end]) => {
            pool.range_begin = Some((*begin).to_owned());
            pool.range_end = Some((*end).to_owned());
        }
        ("default-router", [address]) => pool.default_router = Some((*address).to_owned()),
        ("dns-server", addresses) => {
            pool.dns_servers = addresses.iter().map(|value| (*value).to_owned()).collect();
        }
        ("lease", [seconds]) => pool.lease = seconds.parse().ok(),
        ("bind", [interface]) => pool.interface = Some((*interface).to_owned()),
        ("enable", []) => pool.enabled = Some(true),
        _ => {}
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions report regressions"
)]
mod tests {
    use super::{Pool, parse_pools};

    /// C-08: the indented lines of a later top-level block (`bind`, `enable`) are not
    /// settings of the last DHCP pool.
    #[test]
    fn a_later_blocks_indented_lines_do_not_become_pool_settings() {
        let text = "ip dhcp pool _WEBADMIN\n    range 192.0.2.33 192.0.2.120\n    \
                    default-router 192.0.2.1\n    bind Bridge0\n!\nipv6 subnet Default\n    \
                    bind Bridge1\n    number 0\n!\ncrypto map VPN1\n    enable\n!\n";
        let expected = Pool {
            name: Some("_WEBADMIN".to_owned()),
            range_begin: Some("192.0.2.33".to_owned()),
            range_end: Some("192.0.2.120".to_owned()),
            default_router: Some("192.0.2.1".to_owned()),
            interface: Some("Bridge0".to_owned()),
            ..Pool::default()
        };
        assert_eq!(parse_pools(text), vec![expected]);
    }
}
