//! What a router already has that a new segment must fit: its switch ports and access
//! points, the interface and pool names in use, and the subnets of its interfaces.

use alloc::collections::BTreeSet;
use core::{net::Ipv4Addr, str::FromStr as _};

use kcc_domain::{Result as DomainResult, RouterCtx, dhcp, interfaces};
use serde_json::Value;

/// The router's objects a new segment must fit.
#[derive(Debug, Clone, Default)]
pub(crate) struct Known {
    /// Switch ports, by interface name.
    ports: Vec<String>,
    /// Wi-Fi access points, by interface name.
    access_points: Vec<String>,
    /// Interface and DHCP pool names in use.
    names: BTreeSet<String>,
    /// Interface subnets: name, network and mask.
    subnets: Vec<(String, u32, u32)>,
}

impl Known {
    /// Reads the router's interfaces and DHCP pools through `domain`.
    ///
    /// # Errors
    ///
    /// Returns the read's failure.
    // cancel-safe: reads only.
    pub(crate) async fn read(domain: &RouterCtx) -> DomainResult<Self> {
        let mut known = Self::default();
        for (name, interface) in interfaces::read_interfaces(domain).await? {
            match interface.kind.as_deref() {
                Some("Port") => known.ports.push(name.clone()),
                Some("AccessPoint") => known.access_points.push(name.clone()),
                _ => {}
            }
            let mask = interface.extra.get("mask").and_then(Value::as_str);
            let subnet = interface
                .address
                .as_deref()
                .zip(mask)
                .and_then(|(address, bits)| {
                    Ipv4Addr::from_str(address)
                        .ok()
                        .zip(Ipv4Addr::from_str(bits).ok())
                });
            if let Some((address, bits)) = subnet {
                let mask_bits = u32::from(bits);
                known
                    .subnets
                    .push((name.clone(), u32::from(address) & mask_bits, mask_bits));
            }
            let _: bool = known.names.insert(name);
        }
        for pool in dhcp::read_pools(domain).await? {
            if let Some(name) = pool.name {
                let _: bool = known.names.insert(name);
            }
        }
        Ok(known)
    }

    /// Switch ports, by interface name.
    pub(crate) fn ports(&self) -> &[String] {
        &self.ports
    }

    /// Wi-Fi access points, by interface name.
    pub(crate) fn access_points(&self) -> &[String] {
        &self.access_points
    }

    /// The lowest segment number whose bridge, VLAN and pool names are all free.
    pub(crate) fn free_id(&self) -> Option<u16> {
        (2..=255).find(|id| self.taken(*id).is_none())
    }

    /// The first object name of segment `id` that already exists.
    pub(crate) fn taken(&self, id: u16) -> Option<String> {
        [
            format!("Bridge{id}"),
            format!("Vlan{id}"),
            format!("Pool{id}"),
        ]
        .into_iter()
        .find(|name| self.names.contains(name))
    }

    /// The interface whose subnet overlaps `address`/`mask`, if any.
    pub(crate) fn overlap(&self, address: Ipv4Addr, mask: Ipv4Addr) -> Option<String> {
        let bits = u32::from(mask);
        let network = u32::from(address) & bits;
        self.subnets
            .iter()
            .find(|(_, other, other_bits)| {
                let common = bits & other_bits;
                network & common == other & common
            })
            .map(|(name, _, _)| name.clone())
    }
}
