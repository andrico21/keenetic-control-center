//! What a migration's choices make of its source: the classification the review shows,
//! and the engine's plan of the source without the settings left out.
//!
//! A setting is left out when the review excluded it, when its conflict keeps the
//! router's value, or (for the first apply) when it needs a component the user agreed to
//! install first: the apply installs the components, and the plan is reviewed again.

use alloc::collections::{BTreeMap, BTreeSet};

use kcc_config::config_text::{CliLine, Node, Token, flatten};
use kcc_migrate::{
    planner::{Choices, MigrationMaps, MigrationPlan, PlanError, Planner},
    rules::{ClassifiedItem, Disposition, RuleError},
    source::SourceConfig,
};
use secrecy::SecretString;

use super::{analysis::Analysis, kinds::Maps, record::Record, warnings::component};

/// The classification of every source setting under the current choices.
pub(super) struct Classified {
    /// Every item, in source order.
    items: Vec<ClassifiedItem>,
    /// The items whose value conflicts with the router's when no choice is made.
    conflicts: BTreeSet<usize>,
}

impl Classified {
    /// Classifies the source of `analysis` with the choices of `record` and `passwords`.
    /// The settings the plan keeps are classified as the plan classifies them, on the
    /// source without the left-out ones; the left-out ones as in the whole source.
    ///
    /// # Errors
    ///
    /// Returns a malformed embedded rule set.
    pub(super) fn new(
        analysis: &Analysis,
        record: &Record,
        passwords: &BTreeMap<String, SecretString>,
    ) -> Result<Self, RuleError> {
        let maps = record.maps().cloned().unwrap_or_default();
        let whole = analysis.source();
        let open = analysis.classify(whole, &maps, passwords, &BTreeSet::new())?;
        let conflicts = open
            .iter()
            .filter(|item| item.disposition == Disposition::Conflict)
            .map(|item| item.source_index)
            .collect::<BTreeSet<_>>();
        let keys = overwrite_keys(whole, record.overwrite());
        let items = analysis.classify(whole, &maps, passwords, &keys)?;
        let mut classified = Self { items, conflicts };
        let (planned, kept) = without(whole, &classified.left_out(record));
        for mut item in analysis.classify(&planned, &maps, passwords, &keys)? {
            if let Some(&index) = kept.get(item.source_index)
                && let Some(slot) = classified.items.get_mut(index)
            {
                item.source_index = index;
                *slot = item;
            }
        }
        Ok(classified)
    }

    /// The settings the plan leaves out: the excluded ones, and those that need a
    /// component the user agreed to install first.
    fn left_out(&self, record: &Record) -> BTreeSet<usize> {
        let mut left_out = record.excluded().clone();
        for (name, items) in self.components(record) {
            if record.components().contains(&name) {
                left_out.extend(items);
            }
        }
        left_out
    }

    /// Every item, in source order.
    pub(super) fn items(&self) -> &[ClassifiedItem] {
        &self.items
    }

    /// Whether item `index` conflicts with the router's value.
    pub(super) fn conflicts(&self, index: usize) -> bool {
        self.conflicts.contains(&index)
    }

    /// The conflicts still waiting for a choice.
    pub(super) fn unresolved(&self, record: &Record) -> usize {
        self.conflicts
            .iter()
            .filter(|index| {
                !record.overwrite().contains(index) && !record.excluded().contains(index)
            })
            .count()
    }

    /// The items that need a component, by the component, when not left out.
    pub(super) fn components(&self, record: &Record) -> BTreeMap<String, Vec<usize>> {
        let mut needed: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for item in &self.items {
            if record.excluded().contains(&item.source_index) {
                continue;
            }
            if let Some(name) = component(item) {
                needed
                    .entry(name.to_owned())
                    .or_default()
                    .push(item.source_index);
            }
        }
        needed
    }
}

/// The engine's plan of the source with the left-out settings removed, and the source
/// index of each kept setting.
pub(super) struct Built {
    /// The plan.
    plan: MigrationPlan,
    /// For each setting of the planned source, its index in the whole source.
    kept: Vec<usize>,
}

impl Built {
    /// Plans the source of `analysis` with the choices of `record`, `passwords` and
    /// the URL to reach the router at after management changes.
    ///
    /// # Errors
    ///
    /// Returns the items still blocking the plan, or a malformed rule set.
    pub(super) fn new(
        analysis: &Analysis,
        record: &Record,
        passwords: &BTreeMap<String, SecretString>,
    ) -> Result<Self, PlanError> {
        let classified = Classified::new(analysis, record, passwords)?;
        let (source, kept) = without(analysis.source(), &classified.left_out(record));
        let maps = record.maps().cloned().unwrap_or_default();
        let mut choices = Choices::default();
        choices.new_passwords = passwords.clone();
        choices.overwrite_scalars = overwrite_keys(analysis.source(), record.overwrite());
        choices.reconnect_url = record.reconnect_url().map(str::to_owned);
        let plan = Planner::plan(&source, analysis.target(), &engine_maps(&maps), &choices)?;
        Ok(Self { plan, kept })
    }

    /// The plan.
    pub(super) const fn plan(&self) -> &MigrationPlan {
        &self.plan
    }

    /// The plan, owned.
    pub(super) fn into_plan(self) -> MigrationPlan {
        self.plan
    }

    /// The index in the whole source of the planned source's setting `index`.
    pub(super) fn original(&self, index: usize) -> Option<usize> {
        self.kept.get(index).copied()
    }
}

/// The maps as the planner takes them.
pub(super) fn engine_maps(maps: &Maps) -> MigrationMaps {
    let mut engine = MigrationMaps::default();
    engine.ports = maps.ports().clone();
    engine.radios = maps.radios().clone();
    engine.interfaces = maps.interfaces().clone();
    engine
}

/// The scalar keys of the conflicting settings `overwrite` takes the source's value of:
/// the setting's words without its value, as the engine compares them.
fn overwrite_keys(source: &SourceConfig, overwrite: &BTreeSet<usize>) -> BTreeSet<String> {
    flatten(&source.ast)
        .iter()
        .enumerate()
        .filter(|(index, _)| overwrite.contains(index))
        .filter_map(|(_, line)| scalar_key(line))
        .collect()
}

/// A setting's words without its last one, the value.
fn scalar_key(line: &CliLine) -> Option<String> {
    let words = line
        .tokens
        .iter()
        .flat_map(|token| match token {
            Token::Word(word) => vec![word.as_str()],
            Token::Ns3(payload) => vec!["ns3", payload.as_str()],
            _ => Vec::new(),
        })
        .collect::<Vec<_>>();
    words.split_last().map(|(_, key)| key.join(" "))
}

/// `source` without the settings at `left_out` (and the contexts they emptied), with the
/// whole-source index of each setting kept.
fn without(source: &SourceConfig, left_out: &BTreeSet<usize>) -> (SourceConfig, Vec<usize>) {
    let mut kept = Vec::new();
    let mut next = 0_usize;
    let mut trimmed = source.clone();
    trim(&mut trimmed.ast.nodes, left_out, &mut next, &mut kept);
    (trimmed, kept)
}

/// Removes the leaves at `left_out` below `nodes`, counting leaves from `next` in
/// configuration order and recording the kept ones.
fn trim(
    nodes: &mut Vec<Node>,
    left_out: &BTreeSet<usize>,
    next: &mut usize,
    kept: &mut Vec<usize>,
) {
    nodes.retain_mut(|node| {
        if node.children.is_empty() {
            let index = *next;
            *next = next.saturating_add(1);
            let keep = !left_out.contains(&index);
            if keep {
                kept.push(index);
            }
            keep
        } else {
            trim(&mut node.children, left_out, next, kept);
            !node.children.is_empty()
        }
    });
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use alloc::collections::BTreeSet;
    use core::error::Error;

    use kcc_config::config_text::flatten;
    use kcc_migrate::source::SourceConfig;

    use super::without;

    #[test]
    fn left_out_settings_and_emptied_contexts_go_and_indices_map_back() -> Result<(), Box<dyn Error>>
    {
        let source = SourceConfig::from_bytes(
            b"interface Bridge1\n description one\n ip address 192.0.2.1 255.255.255.0\n!\ninterface Bridge2\n description two\n!\nip host one.example 192.0.2.9\n",
        )?;
        let (trimmed, kept) = without(&source, &BTreeSet::from([1, 2]));
        let lines = flatten(&trimmed.ast)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            lines,
            [
                "interface Bridge1 description one",
                "ip host one.example 192.0.2.9"
            ],
            "the left-out settings and the emptied Bridge2 are gone"
        );
        assert_eq!(kept, [0, 3], "kept settings keep their whole-source index");
        Ok(())
    }
}
