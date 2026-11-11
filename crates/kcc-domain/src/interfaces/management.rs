//! Management-connection detection from router and client topology.

use alloc::collections::{BTreeMap, BTreeSet};
use core::net::{IpAddr, Ipv4Addr};
use std::net::ToSocketAddrs as _;

use kcc_catalog::Risk;
use kcc_rci::{ObjectName, RciBody, RciPath};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{Result, RouterCtx, interfaces::Interface, read_show};

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
pub(super) async fn detect(router: &RouterCtx, name: &ObjectName) -> Result<ManagementVerdict> {
    let interfaces: BTreeMap<String, Interface> =
        read_show(&router.client, &["show", "interface"]).await?;
    let Some(selected) = interfaces.get(name.as_str()) else {
        return Ok(ManagementVerdict::Unknown);
    };
    let hosts = router_hosts(router);
    let direct = classify_direct(name, &hosts, &interfaces);
    if direct != ManagementVerdict::Unknown {
        return Ok(direct);
    }
    if selected.kind.as_deref() != Some("Bridge") {
        return Ok(ManagementVerdict::Unknown);
    }
    let members = bridge_members(router, name).await?;
    let sources = observed_sources(router).await;
    let selected_network = selected
        .address
        .as_deref()
        .and_then(parse_ip_without_prefix)
        .zip(selected.extra.get("mask").and_then(Value::as_str))
        .and_then(|(address, mask)| Network::new(address, mask));
    let Some(network) = selected_network else {
        return Ok(ManagementVerdict::Unknown);
    };
    if sources.iter().any(|source| {
        (source.interface == name.as_str() || members.contains(&source.interface))
            && network.contains(source.address)
    }) {
        Ok(ManagementVerdict::Management)
    } else if sources.is_empty() {
        Ok(ManagementVerdict::Unknown)
    } else {
        Ok(ManagementVerdict::NotManagement)
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

/// Reads bridge members from the configuration projection.
async fn bridge_members(router: &RouterCtx, name: &ObjectName) -> Result<BTreeSet<String>> {
    let RciBody::Json(response) = router
        .client
        .show_rc(json!({"interface":{name.as_str():{"include":{}}}}))
        .await?
    else {
        return Ok(BTreeSet::new());
    };
    let pointer = format!(
        "/show/rc/interface/{}/include",
        name.as_str().replace('~', "~0").replace('/', "~1")
    );
    Ok(response
        .value
        .pointer(&pointer)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            entry
                .get("interface")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect())
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
