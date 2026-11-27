//! The leak rule of the capture self-check, shared by the check and its diagnostics.

use alloc::collections::BTreeSet;
use core::net::{IpAddr, Ipv4Addr};

use crate::anonymize::{
    Identifier, IdentifierKind,
    fold::{contains_folded, fold, percent_decoded},
    ipv4_forms, mac_forms,
    runs::{self, has_foreign_ipv6, learned_prefixes},
};

/// What a text leaks: the identifier kind and, for a learned value, its index among the
/// identifiers the detector was built from.
pub(crate) type Finding = (IdentifierKind, Option<usize>);

/// Every learned identifier in each spelling the self-check looks for.
pub(crate) struct Detector<'identifiers> {
    /// The identifiers, for naming the one behind an address hit.
    identifiers: &'identifiers [Identifier],
    /// Folded spellings with their kind and identifier index.
    needles: Vec<(String, IdentifierKind, usize)>,
    /// Learned IPv4 addresses, also looked for in other spellings.
    ipv4: BTreeSet<Ipv4Addr>,
    /// `/48` prefixes of learned IPv6 addresses, also looked for inside other addresses.
    prefixes: BTreeSet<[u16; 3]>,
}

impl<'identifiers> Detector<'identifiers> {
    /// Prepares every spelling of `identifiers`.
    pub(crate) fn new(identifiers: &'identifiers [Identifier]) -> Self {
        let mut needles = Vec::new();
        let mut ipv4 = BTreeSet::new();
        let mut prefixes = BTreeSet::new();
        for (index, identifier) in identifiers.iter().enumerate() {
            let spellings = if identifier.kind == IdentifierKind::Mac {
                mac_forms::spellings(&identifier.value).to_vec()
            } else {
                vec![fold(&identifier.value)]
            };
            needles.extend(
                spellings
                    .into_iter()
                    .map(|needle| (needle, identifier.kind, index)),
            );
            match identifier.value.parse::<IpAddr>() {
                Ok(IpAddr::V4(address)) => {
                    let _: bool = ipv4.insert(address);
                }
                Ok(IpAddr::V6(address)) => prefixes.extend(learned_prefixes(address)),
                Err(_) => {}
            }
        }
        Self {
            identifiers,
            needles,
            ipv4,
            prefixes,
        }
    }

    /// What `text` leaks under the self-check's rule: a learned value in any of its
    /// spellings, as written or percent-decoded, with Unicode case ignored; then a learned
    /// IPv4 address in another spelling, a learned IPv6 `/48` inside another address, or a
    /// foreign IPv6 address.
    pub(crate) fn finding(&self, text: &str) -> Option<Finding> {
        let decoded = text
            .contains(['%', '+'])
            .then(|| fold(&percent_decoded(text)));
        let haystacks: Vec<String> = [Some(fold(text)), decoded].into_iter().flatten().collect();
        if let Some((_, kind, index)) = self.needles.iter().find(|(needle, _, _)| {
            haystacks
                .iter()
                .any(|haystack| contains_folded(haystack, needle))
        }) {
            return Some((*kind, Some(*index)));
        }
        let address = |ipv4: &BTreeSet<Ipv4Addr>, prefixes: &BTreeSet<[u16; 3]>| {
            haystacks.iter().any(|haystack| {
                ipv4_forms::holds_learned(haystack, ipv4) || runs::holds_prefix(haystack, prefixes)
            })
        };
        if address(&self.ipv4, &self.prefixes) {
            let index = self.identifiers.iter().position(|identifier| {
                match identifier.value.parse::<IpAddr>() {
                    Ok(IpAddr::V4(learned)) => {
                        address(&BTreeSet::from([learned]), &BTreeSet::new())
                    }
                    Ok(IpAddr::V6(learned)) => address(
                        &BTreeSet::new(),
                        &learned_prefixes(learned).into_iter().collect(),
                    ),
                    Err(_) => false,
                }
            });
            return Some((IdentifierKind::Address, index));
        }
        haystacks
            .iter()
            .any(|haystack| has_foreign_ipv6(haystack))
            .then_some((IdentifierKind::Address, None))
    }
}
