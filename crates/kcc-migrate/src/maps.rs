//! Editable, serializable migration mapping proposals.

use alloc::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    interface_names,
    inventory::{LogicalInterface, PhysicalPort, PortRole, Radio},
};

/// One editable mapping decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct MapEntry {
    /// Source object id or name.
    pub source: String,
    /// Proposed target object id or name; `None` means unmapped.
    pub target: Option<String>,
}

impl MapEntry {
    /// Creates one explicit mapping decision.
    #[inline]
    #[must_use]
    pub const fn new(source: String, target: Option<String>) -> Self {
        Self { source, target }
    }
}

/// Physical-port mapping proposal.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct PortMap {
    /// Editable decisions in source port order.
    pub entries: Vec<MapEntry>,
}

impl PortMap {
    /// Proposes WAN-to-WAN and numbered LAN-to-LAN mappings.
    #[inline]
    #[must_use]
    pub fn propose(source: &[PhysicalPort], target: &[PhysicalPort]) -> Self {
        let entries = source
            .iter()
            .map(|source_port| MapEntry {
                source: source_port.id.clone(),
                target: target
                    .iter()
                    .find(|target_port| roles_match(&source_port.role, &target_port.role))
                    .map(|target_port| target_port.id.clone()),
            })
            .collect();
        Self { entries }
    }
}

/// Wi-Fi-radio mapping proposal.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct RadioMap {
    /// Editable decisions in source radio order.
    pub entries: Vec<MapEntry>,
}

impl RadioMap {
    /// Proposes radios with at least one matching frequency band.
    #[inline]
    #[must_use]
    pub fn propose(source: &[Radio], target: &[Radio]) -> Self {
        let entries = source
            .iter()
            .map(|source_radio| MapEntry {
                source: source_radio.id.clone(),
                target: target
                    .iter()
                    .find(|target_radio| !source_radio.bands.is_disjoint(&target_radio.bands))
                    .map(|target_radio| target_radio.id.clone()),
            })
            .collect();
        Self { entries }
    }
}

/// Logical-interface mapping proposal.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct InterfaceMap {
    /// Editable decisions in source interface order.
    pub entries: Vec<MapEntry>,
}

impl InterfaceMap {
    /// Keeps source names unless they collide with a differently typed target default.
    #[inline]
    #[must_use]
    pub fn propose(source: &[LogicalInterface], target: &[LogicalInterface]) -> Self {
        let defaults = target
            .iter()
            .filter(|interface| interface.target_default)
            .map(|interface| (interface.name.as_str(), interface.kind.as_str()))
            .collect::<BTreeMap<_, _>>();
        let entries = source
            .iter()
            .map(|source_interface| {
                let collision = defaults
                    .get(source_interface.name.as_str())
                    .is_some_and(|kind| *kind != source_interface.kind);
                MapEntry {
                    source: source_interface.name.clone(),
                    target: (!collision).then(|| source_interface.name.clone()),
                }
            })
            .collect();
        Self { entries }
    }
}

/// The mapping decision that applies to one configuration word.
pub(crate) struct WordMapping<'word, Decision> {
    /// The mapped object name the word starts with.
    name: &'word str,
    /// The rest of the word after `name`, kept as it is: empty or `/<child>`.
    rest: &'word str,
    /// The decision recorded for `name`.
    decision: Decision,
}

impl<'word, Decision: Copy> WordMapping<'word, Decision> {
    /// Finds the decision for `word`: its exact entry, or else, for a Wi-Fi access point
    /// `WifiMaster<n>/<child>`, the entry of its radio `WifiMaster<n>`.
    pub(crate) fn find(mappings: &BTreeMap<&str, Decision>, word: &'word str) -> Option<Self> {
        if let Some(decision) = mappings.get(word) {
            return Some(Self {
                name: word,
                rest: "",
                decision: *decision,
            });
        }
        let (name, rest) = word.split_at_checked(word.find('/')?)?;
        if !interface_names::is_radio(name) {
            return None;
        }
        mappings.get(name).map(|decision| Self {
            name,
            rest,
            decision: *decision,
        })
    }

    /// The mapped object name the word starts with.
    pub(crate) const fn name(&self) -> &'word str {
        self.name
    }

    /// The rest of the word after [`Self::name`]: empty or `/<child>`.
    pub(crate) const fn rest(&self) -> &'word str {
        self.rest
    }

    /// The decision recorded for [`Self::name`].
    pub(crate) const fn decision(&self) -> Decision {
        self.decision
    }
}

/// Matches only equivalent physical roles and equal LAN numbers.
fn roles_match(source: &PortRole, target: &PortRole) -> bool {
    match (source, target) {
        (PortRole::Wan, PortRole::Wan)
        | (PortRole::Sfp, PortRole::Sfp)
        | (PortRole::Dsl, PortRole::Dsl) => true,
        (PortRole::Lan(source_number), PortRole::Lan(target_number)) => {
            source_number == target_number
        }
        (PortRole::Other(source_name), PortRole::Other(target_name)) => source_name == target_name,
        (
            PortRole::Wan | PortRole::Lan(_) | PortRole::Sfp | PortRole::Dsl | PortRole::Other(_),
            _,
        ) => false,
    }
}
