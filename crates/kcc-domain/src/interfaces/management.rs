//! Management-connection detection from router and client topology.

use alloc::collections::{BTreeMap, BTreeSet};
use core::net::{IpAddr, Ipv4Addr};

use kcc_catalog::Risk;
use kcc_rci::{ObjectName, RciBody, RciPath};
use serde::Deserialize;
use serde_json::Value;

use crate::{DomainError, Result, RouterCtx, interfaces::Interface, read_show};

/// Result of management-connection detection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public name is the vocabulary the Web, MCP and CLI front ends use"
)]
pub enum ManagementVerdict {
    /// Evidence identifies this interface as carrying management traffic.
    Management,
    /// Evidence identifies another interface as carrying management traffic.
    NotManagement,
    /// Available evidence cannot identify the management interface.
    Unknown,
}

impl ManagementVerdict {
    /// Maps the verdict to operation risk. A verdict that cannot tell which interface
    /// carries kcc's connection fails closed: the change may cut kcc off.
    #[inline]
    #[must_use]
    pub const fn risk(self) -> Risk {
        match self {
            Self::Management | Self::Unknown => Risk::Management,
            Self::NotManagement => Risk::Write,
        }
    }
}

/// Detects direct ownership of the address the client is pinned to, then bridge topology
/// evidence; a bridge whose evidence cannot decide counts as carrying management.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]), or when a reply or a plan
/// does not have the expected shape ([`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, topology reads do not change router state.
pub(super) async fn detect(router: &RouterCtx, name: &ObjectName) -> Result<ManagementVerdict> {
    let interfaces: BTreeMap<String, Interface> =
        read_show(&router.client, &["show", "interface"]).await?;
    let hosts = router
        .client
        .pinned_addresses()
        .map(|address| address.to_canonical())
        .collect::<BTreeSet<_>>();
    if hosts.is_empty() {
        return Ok(ManagementVerdict::Management);
    }
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
        match classify_bridge(selected, &candidate, members, &sources) {
            ManagementVerdict::Management | ManagementVerdict::Unknown => {
                return Ok(ManagementVerdict::Management);
            }
            ManagementVerdict::NotManagement if candidate == name.as_str() => {
                verdict = ManagementVerdict::NotManagement;
            }
            ManagementVerdict::NotManagement => {}
        }
    }
    Ok(verdict)
}

/// Raises a generated CLI plan to management risk for every interface identity it renders.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, classification performs read-only topology requests.
pub(crate) async fn classify_generated(router: &RouterCtx, lines: &[&str]) -> Result<Risk> {
    let mut names = BTreeSet::new();
    for line in lines {
        let mut words = line.split_whitespace();
        let first = words.next();
        let interface = match first {
            Some("interface") => words.next(),
            Some("no") if words.next() == Some("interface") => words.next(),
            Some(_) | None => None,
        };
        if let Some(name) = interface {
            let _: bool = names.insert(name.to_owned());
        }
        let mut members = line.split_whitespace();
        while let Some(word) = members.next() {
            if matches!(word, "include" | "inherit")
                && let Some(member) = members.next()
            {
                let _: bool = names.insert(member.to_owned());
            }
        }
    }
    for name in names {
        let object = ObjectName::try_from(name).map_err(|_error| DomainError::InvalidResponse)?;
        if detect(router, &object).await?.risk() == Risk::Management {
            return Ok(Risk::Management);
        }
    }
    Ok(Risk::Write)
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
///
/// Once an interface owns an address kcc is pinned to, every other name is decided, a name
/// the router does not list yet included. A name is the owner when it equals the owner's key,
/// `id` or `interface-name` regardless of case, so an alias of the owner still counts as it.
#[inline]
#[must_use]
pub fn classify_direct(
    name: &ObjectName,
    hosts: &BTreeSet<IpAddr>,
    interfaces: &BTreeMap<String, Interface>,
) -> ManagementVerdict {
    let mut owners = interfaces
        .iter()
        .filter(|(_key, interface)| {
            interface
                .address
                .as_deref()
                .and_then(parse_ip_without_prefix)
                .is_some_and(|address| hosts.contains(&address))
        })
        .peekable();
    if owners.peek().is_none() {
        return ManagementVerdict::Unknown;
    }
    let named = owners.any(|(key, interface)| {
        [
            Some(key.as_str()),
            interface.id.as_deref(),
            interface
                .extra
                .get("interface-name")
                .and_then(Value::as_str),
        ]
        .into_iter()
        .flatten()
        .any(|alias| alias.eq_ignore_ascii_case(name.as_str()))
    });
    if named {
        ManagementVerdict::Management
    } else {
        ManagementVerdict::NotManagement
    }
}

/// Reads ARP and hotspot source-address evidence best-effort.
// NOT cancel-safe: it only sends `show` reads, but it may sign in first, and a sign-in dropped
// mid-way can leave an orphaned router session.
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

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "unit tests use assertions while propagating fixture decoding failures"
)]
mod tests {
    use alloc::collections::BTreeSet;
    use core::net::{IpAddr, Ipv4Addr};

    use serde_json::json;

    use super::{ManagementVerdict, ObservedSource, classify_bridge};
    use crate::interfaces::Interface;

    fn bridge() -> Result<Interface, serde_json::Error> {
        serde_json::from_value(json!({
            "id":"Bridge7",
            "type":"Bridge",
            "address":"198.51.100.1",
            "mask":"255.255.255.0"
        }))
    }

    #[test]
    fn bridge_without_observed_sources_is_unknown() -> Result<(), serde_json::Error> {
        let members = BTreeSet::from(["WifiMaster0/AccessPoint0".to_owned()]);

        let verdict = classify_bridge(&bridge()?, "Bridge7", Some(&members), &[]);

        assert_eq!(verdict, ManagementVerdict::Unknown);
        Ok(())
    }

    #[test]
    fn bridge_with_unrelated_source_is_not_management() -> Result<(), serde_json::Error> {
        let members = BTreeSet::from(["WifiMaster0/AccessPoint1".to_owned()]);
        let sources = [ObservedSource {
            address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            interface: "Bridge0".to_owned(),
        }];

        let verdict = classify_bridge(&bridge()?, "Bridge7", Some(&members), &sources);

        assert_eq!(verdict, ManagementVerdict::NotManagement);
        Ok(())
    }

    #[test]
    fn source_on_bridge_or_member_is_management() -> Result<(), serde_json::Error> {
        let members = BTreeSet::from(["WifiMaster0/AccessPoint0".to_owned()]);
        for interface in ["Bridge7", "WifiMaster0/AccessPoint0"] {
            let sources = [ObservedSource {
                address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25)),
                interface: interface.to_owned(),
            }];

            let verdict = classify_bridge(&bridge()?, "Bridge7", Some(&members), &sources);

            assert_eq!(verdict, ManagementVerdict::Management, "{interface}");
        }
        Ok(())
    }
}
