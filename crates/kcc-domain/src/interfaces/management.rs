//! Management-connection detection from router and client topology.

use alloc::collections::{BTreeMap, BTreeSet};
use core::net::{IpAddr, Ipv4Addr};
use std::net::ToSocketAddrs as _;

use kcc_catalog::Risk;
use kcc_rci::{ObjectName, RciBody, RciPath};
use serde::Deserialize;
use serde_json::Value;

use crate::{DomainError, Result, RouterCtx, interfaces::Interface, read_show};

/// Result of management-connection detection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ManagementVerdict {
    /// Evidence identifies this interface as carrying management traffic.
    Management,
    /// Evidence identifies another interface as carrying management traffic.
    NotManagement,
    /// Available evidence cannot identify the management interface.
    Unknown,
}

impl ManagementVerdict {
    /// Maps the verdict to operation risk, applying the conservative Bridge0 fallback.
    #[inline]
    #[must_use]
    pub fn risk(self, name: &ObjectName) -> Risk {
        match self {
            Self::Management => Risk::Management,
            Self::Unknown if name.as_str() == "Bridge0" => Risk::Management,
            Self::NotManagement | Self::Unknown => Risk::Write,
        }
    }
}

/// Detects direct origin-address ownership and bridge topology evidence.
// cancel-safe: topology reads do not change router state.
pub(super) async fn detect(router: &RouterCtx, name: &ObjectName) -> Result<ManagementVerdict> {
    let interfaces: BTreeMap<String, Interface> =
        read_show(&router.client, &["show", "interface"]).await?;
    let hosts = router_hosts(router);
    let direct = classify_direct(name, &hosts, &interfaces);
    if direct == ManagementVerdict::Management {
        return Ok(direct);
    }
    let membership = super::membership::read(router).await?;
    let mut candidates = BTreeSet::from([name.as_str().to_owned()]);
    loop {
        let before = candidates.len();
        for (bridge, members) in &membership {
            if members.iter().any(|member| candidates.contains(member)) {
                let _: bool = candidates.insert(bridge.clone());
            }
        }
        if candidates.len() == before {
            break;
        }
    }
    let sources = observed_sources(router).await;
    let mut verdict = direct;
    for candidate in candidates {
        let Some(selected) = interfaces.get(&candidate) else {
            continue;
        };
        let object = ObjectName::try_from(candidate.clone())
            .map_err(|_error| DomainError::InvalidResponse)?;
        if classify_direct(&object, &hosts, &interfaces) == ManagementVerdict::Management {
            return Ok(ManagementVerdict::Management);
        }
        if selected.kind.as_deref() != Some("Bridge") {
            continue;
        }
        let members = membership.get(&candidate);
        let bridge = classify_bridge(selected, &candidate, members, &sources);
        if bridge == ManagementVerdict::Management
            || (candidate != name.as_str() && bridge.risk(&object) == Risk::Management)
        {
            return Ok(ManagementVerdict::Management);
        }
        if candidate == name.as_str() {
            verdict = bridge;
        }
    }
    Ok(verdict)
}

/// Classifies a bridge using the shared membership union and observed source addresses.
fn classify_bridge(
    selected: &Interface,
    name: &str,
    members: Option<&BTreeSet<String>>,
    sources: &[ObservedSource],
) -> ManagementVerdict {
    let selected_network = selected
        .address
        .as_deref()
        .and_then(parse_ip_without_prefix)
        .zip(selected.extra.get("mask").and_then(Value::as_str))
        .and_then(|(address, mask)| Network::new(address, mask));
    let Some(network) = selected_network else {
        return ManagementVerdict::Unknown;
    };
    if sources.iter().any(|source| {
        (source.interface == name || members.is_some_and(|names| names.contains(&source.interface)))
            && network.contains(source.address)
    }) {
        ManagementVerdict::Management
    } else if sources.is_empty() {
        ManagementVerdict::Unknown
    } else {
        ManagementVerdict::NotManagement
    }
}

/// Classifies direct router-origin ownership from already-read interface data.
pub fn classify_direct(
    name: &ObjectName,
    hosts: &BTreeSet<IpAddr>,
    interfaces: &BTreeMap<String, Interface>,
) -> ManagementVerdict {
    let Some(selected) = interfaces.get(name.as_str()) else {
        return ManagementVerdict::Unknown;
    };
    if selected
        .address
        .as_deref()
        .and_then(parse_ip_without_prefix)
        .is_some_and(|address| hosts.contains(&address))
    {
        return ManagementVerdict::Management;
    }
    if interfaces.values().any(|interface| {
        interface
            .address
            .as_deref()
            .and_then(parse_ip_without_prefix)
            .is_some_and(|address| hosts.contains(&address))
    }) {
        ManagementVerdict::NotManagement
    } else {
        ManagementVerdict::Unknown
    }
}

/// Reads ARP and hotspot source-address evidence best-effort.
async fn observed_sources(router: &RouterCtx) -> Vec<ObservedSource> {
    let mut sources = Vec::new();
    for segments in [["show", "ip", "arp"], ["show", "ip", "hotspot"]] {
        let Ok(path) = RciPath::from_segments(segments) else {
            continue;
        };
        let Ok(RciBody::Json(response)) = router.client.show(&path, &()).await else {
            continue;
        };
        if let Ok(rows) = serde_json::from_value::<Vec<ObservedRow>>(response.value) {
            sources.extend(rows.into_iter().filter_map(ObservedRow::into_source));
        }
    }
    sources
}

/// Resolves the router-origin host to comparable IP addresses.
fn router_hosts(router: &RouterCtx) -> BTreeSet<IpAddr> {
    let Some(host) = router.client.router_url().host() else {
        return BTreeSet::new();
    };
    if let Some(address) = parse_ip_without_prefix(&host) {
        return BTreeSet::from([address]);
    }
    (host.as_str(), 0_u16).to_socket_addrs().map_or_else(
        |_error| BTreeSet::new(),
        |addresses| addresses.map(|address| address.ip()).collect(),
    )
}

/// Parses an IP while tolerating a CIDR suffix.
fn parse_ip_without_prefix(value: &str) -> Option<IpAddr> {
    value.split('/').next()?.parse().ok()
}

/// Tolerant observed-host row.
#[derive(Deserialize)]
struct ObservedRow {
    /// ARP address.
    address: Option<IpAddr>,
    /// Hotspot address.
    ip: Option<IpAddr>,
    /// Carrying interface.
    interface: Option<String>,
}

impl ObservedRow {
    /// Converts complete row data into topology evidence.
    fn into_source(self) -> Option<ObservedSource> {
        Some(ObservedSource {
            address: self.address.or(self.ip)?,
            interface: self.interface?,
        })
    }
}

/// Observed source address and carrying interface.
struct ObservedSource {
    /// Source address.
    address: IpAddr,
    /// Carrying interface.
    interface: String,
}

/// Contiguous IPv4 subnet.
struct Network {
    /// Network bits.
    network: u32,
    /// Mask bits.
    mask: u32,
}

impl Network {
    /// Builds a network from an address and dotted mask.
    fn new(address: IpAddr, mask_text: &str) -> Option<Self> {
        let IpAddr::V4(ipv4_address) = address else {
            return None;
        };
        let mask_bits = u32::from(mask_text.parse::<Ipv4Addr>().ok()?);
        let inverted = !mask_bits;
        if inverted != 0 && !inverted.checked_add(1).is_some_and(u32::is_power_of_two) {
            return None;
        }
        Some(Self {
            network: u32::from(ipv4_address) & mask_bits,
            mask: mask_bits,
        })
    }

    /// Tests subnet membership.
    fn contains(&self, address: IpAddr) -> bool {
        let IpAddr::V4(ipv4_address) = address else {
            return false;
        };
        u32::from(ipv4_address) & self.mask == self.network
    }
}
