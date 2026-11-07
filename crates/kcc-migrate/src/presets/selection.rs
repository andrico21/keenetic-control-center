//! Dependency closure for settings-group selections.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};

use kcc_config::config_text::{CliLine, Token};

use super::{
    glob,
    groups::{GroupError, SettingsGroup},
};

/// Expands group-id dependencies transitively.
///
/// # Errors
///
/// Returns [`GroupError::UnknownGroup`] when a requested dependency is absent.
pub(super) fn close_group_dependencies<'group>(
    selected: &[&str],
    by_id: &BTreeMap<&'group str, &'group SettingsGroup>,
) -> Result<BTreeSet<&'group str>, GroupError> {
    let mut closed = BTreeSet::new();
    let mut pending = selected
        .iter()
        .map(|id| (*id).to_owned())
        .collect::<VecDeque<_>>();
    while let Some(id) = pending.pop_front() {
        let group = by_id
            .get(id.as_str())
            .ok_or_else(|| GroupError::UnknownGroup { id: id.clone() })?;
        if closed.insert(group.id.as_str()) {
            pending.extend(
                group
                    .depends_on
                    .iter()
                    .filter(|dependency| by_id.contains_key(dependency.as_str()))
                    .cloned(),
            );
        }
    }
    Ok(closed)
}

/// Finds all lines directly owned by selected groups.
pub(super) fn matching_line_indices(
    lines: &[CliLine],
    selected: &BTreeSet<&str>,
    by_id: &BTreeMap<&str, &SettingsGroup>,
) -> BTreeSet<usize> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            let line_words = words(line);
            selected
                .iter()
                .filter_map(|id| by_id.get(id))
                .any(|group| {
                    group
                        .include
                        .iter()
                        .any(|pattern| glob::matches(pattern, &line_words))
                })
                .then_some(index)
        })
        .collect()
}

/// Pulls referenced definitions and named schedules to a fixed point.
pub(super) fn close_line_dependencies(
    lines: &[CliLine],
    selected: &BTreeSet<&str>,
    by_id: &BTreeMap<&str, &SettingsGroup>,
    included: &mut BTreeSet<usize>,
) {
    loop {
        let references = referenced_words(lines, included);
        let dependencies = selected
            .iter()
            .filter_map(|id| by_id.get(id))
            .flat_map(|group| group.depends_on.iter())
            .filter(|dependency| !by_id.contains_key(dependency.as_str()));
        let before = included.len();
        for (index, line) in lines.iter().enumerate() {
            let line_words = words(line);
            let schedule = line_words.first().is_some_and(|word| *word == "schedule");
            let referenced_schedule = schedule
                && line_words
                    .get(1)
                    .is_some_and(|name| references.contains(name));
            let referenced_dependency = dependencies.clone().any(|pattern| {
                dependency_identity(pattern, &line_words)
                    .is_some_and(|name| references.contains(name))
            });
            if referenced_schedule || referenced_dependency {
                let _inserted = included.insert(index);
            }
        }
        if included.len() == before {
            break;
        }
    }
}

/// Returns the object-name word captured by a dependency pattern.
fn dependency_identity<'line>(pattern: &str, words: &'line [&str]) -> Option<&'line str> {
    if !glob::matches(pattern, words) {
        return None;
    }
    pattern
        .split_whitespace()
        .position(|part| part.contains('*'))
        .and_then(|index| words.get(index))
        .copied()
}

/// Collects ordinary words from selected lines.
fn referenced_words<'line>(
    lines: &'line [CliLine],
    included: &BTreeSet<usize>,
) -> BTreeSet<&'line str> {
    included
        .iter()
        .filter_map(|index| lines.get(*index))
        .flat_map(words)
        .collect()
}

/// Returns ordinary command words and the typed NS3 marker.
fn words(line: &CliLine) -> Vec<&str> {
    line.tokens
        .iter()
        .filter_map(|token| match token {
            Token::Word(value) => Some(value.as_str()),
            Token::Ns3(_) => Some("ns3"),
            _ => None,
        })
        .collect()
}
