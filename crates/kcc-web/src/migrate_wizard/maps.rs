//! The three maps of step 3: what each source port, radio and interface becomes on the
//! target. A source object without a target keeps its name.
//!
//! A router source has an inventory of its own (read once, kept in the session), so its
//! ports and radios are proposed the engine's way (`kcc_migrate::maps`): by role (WAN to
//! WAN, LAN n to LAN n) and by a band in common. A file or a backup has no hardware to
//! read: its ports and radios are the ones its configuration names, kept under their
//! name where the target has them. A switch port named by its number (`interface 1`) is
//! a port row for either source, unmapped unless the target has that port, so the
//! default maps plan it as the CLI and MCP do. Interfaces keep their names unless the
//! target has the name for another kind of interface.

use alloc::collections::{BTreeMap, BTreeSet};

use kcc_migrate::{
    inventory::{PhysicalPort, Radio, TargetInventory},
    maps::{InterfaceMap, MapEntry, PortMap, RadioMap},
    source::SourceConfig,
};

use super::kinds::Maps;
use crate::wizard::names::{
    configured_interfaces, interface_kind, is_port, is_radio, is_switch_port, map_of, valid_name,
};

/// Which map a row belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// Physical ports.
    Port,
    /// Wi-Fi radios.
    Radio,
    /// Logical interfaces.
    Interface,
}

impl Kind {
    /// The form field prefix of the kind's rows.
    pub(super) const fn prefix(self) -> &'static str {
        match self {
            Self::Port => "port",
            Self::Radio => "radio",
            Self::Interface => "interface",
        }
    }
}

/// What the maps can name: both sides' objects.
pub(super) struct Sides<'call> {
    /// The source's own inventory, when the source is a router.
    hardware: Option<&'call TargetInventory>,
    /// The source configuration.
    config: &'call SourceConfig,
    /// The target's inventory.
    target: &'call TargetInventory,
}

/// Why a submitted map entry was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    /// Not one of the target's objects of the kind.
    Unknown,
    /// Already chosen for an earlier source object.
    Taken,
    /// The radios share no band.
    Band,
    /// Not a valid interface name.
    Name,
    /// The target has the name for another kind of interface.
    OtherKind,
}

impl<'call> Sides<'call> {
    /// The sides of a migration.
    pub(super) const fn new(
        hardware: Option<&'call TargetInventory>,
        config: &'call SourceConfig,
        target: &'call TargetInventory,
    ) -> Self {
        Self {
            hardware,
            config,
            target,
        }
    }

    /// The target's ports.
    pub(super) fn target_ports(&self) -> &[PhysicalPort] {
        &self.target.ports
    }

    /// The target's radios.
    pub(super) fn target_radios(&self) -> &[Radio] {
        &self.target.radios
    }

    /// Whether the source's hardware is known (a router source).
    pub(super) const fn hardware_known(&self) -> bool {
        self.hardware.is_some()
    }

    /// The source port `id`, when its hardware is known.
    pub(super) fn source_port(&self, id: &str) -> Option<&PhysicalPort> {
        self.hardware?.ports.iter().find(|port| port.id == id)
    }

    /// The source radio `id`, when its hardware is known.
    pub(super) fn source_radio(&self, id: &str) -> Option<&Radio> {
        self.hardware?.radios.iter().find(|radio| radio.id == id)
    }

    /// The proposed maps.
    pub(super) fn propose(&self) -> Maps {
        let named = configured_interfaces(self.config);
        let port_ids = self
            .target
            .ports
            .iter()
            .map(|port| port.id.clone())
            .collect::<Vec<_>>();
        let (ports, radios) = self.hardware.map_or_else(
            || {
                let radio_ids = self
                    .target
                    .radios
                    .iter()
                    .map(|radio| radio.id.clone())
                    .collect::<Vec<_>>();
                (
                    entries(
                        named
                            .iter()
                            .filter(|name| is_port(name, &self.target.ports)),
                        &port_ids,
                    ),
                    entries(named.iter().filter(|name| is_radio(name)), &radio_ids),
                )
            },
            |source| {
                let mut ports = PortMap::propose(&source.ports, &self.target.ports);
                let switch_ports: PortMap = entries(
                    named.iter().filter(|name| {
                        is_switch_port(name) && !source.ports.iter().any(|port| port.id == **name)
                    }),
                    &port_ids,
                );
                ports.entries.extend(switch_ports.entries);
                (
                    ports,
                    distinct_radios(
                        RadioMap::propose(&source.radios, &self.target.radios),
                        &source.radios,
                        &self.target.radios,
                    ),
                )
            },
        );
        let mapped = ports
            .entries
            .iter()
            .chain(&radios.entries)
            .map(|entry| entry.source.as_str())
            .collect::<BTreeSet<_>>();
        let target_kinds = self.target_kinds();
        let interfaces: InterfaceMap = map_of(
            named
                .iter()
                .filter(|name| !mapped.contains(name.as_str()))
                .map(|name| {
                    let collides = target_kinds
                        .get(name.as_str())
                        .is_some_and(|kind| *kind != interface_kind(name));
                    (name.clone(), (!collides).then(|| name.clone()))
                }),
        );
        Maps::new(ports, radios, interfaces)
    }

    /// Checks `value`, chosen for the row of `kind` with source `source`, given the
    /// targets the earlier rows took; empty means unmapped.
    ///
    /// # Errors
    ///
    /// Returns why the value cannot be the source's target.
    pub(super) fn check(
        &self,
        kind: Kind,
        source: &str,
        value: &str,
        taken: &BTreeSet<String>,
    ) -> Result<Option<String>, Refusal> {
        if value.is_empty() {
            return Ok(None);
        }
        if taken.contains(value) {
            return Err(Refusal::Taken);
        }
        match kind {
            Kind::Port => self
                .target
                .ports
                .iter()
                .any(|port| port.id == value)
                .then(|| Some(value.to_owned()))
                .ok_or(Refusal::Unknown),
            Kind::Radio => {
                let target = self
                    .target
                    .radios
                    .iter()
                    .find(|radio| radio.id == value)
                    .ok_or(Refusal::Unknown)?;
                let shares = self.source_radio(source).is_none_or(|radio| {
                    radio.bands.is_empty()
                        || target.bands.is_empty()
                        || !radio.bands.is_disjoint(&target.bands)
                });
                shares.then(|| Some(value.to_owned())).ok_or(Refusal::Band)
            }
            Kind::Interface => {
                if !valid_name(value) {
                    return Err(Refusal::Name);
                }
                let other = self
                    .target_kinds()
                    .get(value)
                    .is_some_and(|known| *known != interface_kind(source));
                (!other)
                    .then(|| Some(value.to_owned()))
                    .ok_or(Refusal::OtherKind)
            }
        }
    }

    /// The kind of every interface the target's running configuration has.
    fn target_kinds(&self) -> BTreeMap<&str, &str> {
        self.target
            .interfaces
            .iter()
            .map(|interface| (interface.name.as_str(), interface.kind.as_str()))
            .collect()
    }
}

/// The entries of `map` as `(source, target)` pairs.
pub(super) fn pairs(entries: &[MapEntry]) -> Vec<(String, Option<String>)> {
    entries
        .iter()
        .map(|entry| (entry.source.clone(), entry.target.clone()))
        .collect()
}

/// Entries keeping each of `names` under its own name where `targets` has it.
fn entries<'name, M, N>(names: N, targets: &[String]) -> M
where
    M: FromIterator<MapEntry>,
    N: Iterator<Item = &'name String>,
{
    map_of(names.map(|name| {
        let kept = targets.contains(name);
        (name.clone(), kept.then(|| name.clone()))
    }))
}

/// `proposed` with every target radio taken at most once.
///
/// Each source radio keeps the target radio of its own name, else the engine's
/// proposal, else another radio with a band in common, while one is still free;
/// otherwise it stays unmapped.
fn distinct_radios(mut proposed: RadioMap, source: &[Radio], target: &[Radio]) -> RadioMap {
    let mut taken = BTreeSet::new();
    for entry in &mut proposed.entries {
        let bands = source
            .iter()
            .find(|radio| radio.id == entry.source)
            .map(|radio| &radio.bands);
        let shares = |radio: &&Radio| {
            bands.is_none_or(|known| {
                known.is_empty() || radio.bands.is_empty() || !known.is_disjoint(&radio.bands)
            })
        };
        let same = target
            .iter()
            .filter(shares)
            .find(|radio| radio.id == entry.source)
            .map(|radio| radio.id.clone());
        let others = target.iter().filter(shares).map(|radio| radio.id.clone());
        entry.target = same
            .into_iter()
            .chain(entry.target.clone())
            .chain(others)
            .find(|candidate| !taken.contains(candidate));
        if let Some(chosen) = &entry.target {
            let _: bool = taken.insert(chosen.clone());
        }
    }
    proposed
}
