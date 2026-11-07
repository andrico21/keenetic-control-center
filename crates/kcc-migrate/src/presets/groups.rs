//! Embedded settings-group definitions and dependency closure.

use alloc::collections::BTreeSet;
use std::sync::LazyLock;

use kcc_config::config_text::{Ast, CliLine, flatten};
use serde::Deserialize;
use thiserror::Error;

use super::{glob, selection};

/// Embedded settings-group document.
const GROUPS_TOML: &str = include_str!("../../rules/groups.toml");

/// Secret treatment required by a settings group.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum SecretHandling {
    /// The group contains no known secrets.
    None,
    /// Secrets remain protected in encrypted preset storage.
    PreserveEncrypted,
    /// WireGuard private keys are regenerated unless explicitly retained.
    RegenerateWireguard,
}

/// One data-driven settings group.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
pub struct SettingsGroup {
    /// Stable group identifier.
    pub id: String,
    /// Localization key for the displayed title.
    pub title_key: String,
    /// Flattened-command patterns owned by this group.
    pub include: Vec<String>,
    /// Group ids or referenced-definition patterns pulled in automatically.
    pub depends_on: Vec<String>,
    /// Secret treatment applied by capture and planning.
    pub secret_handling: SecretHandling,
}

/// Selected groups and their dependency-closed source lines.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct GroupSelection {
    /// Explicit and automatically included group ids.
    pub groups: Vec<String>,
    /// Source-ordered, dependency-closed flattened lines.
    pub lines: Vec<CliLine>,
}

/// Embedded group loading or selection failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum GroupError {
    /// The embedded document is malformed.
    #[error("embedded preset settings groups are invalid")]
    InvalidToml,
    /// A group has missing or duplicate identity or pattern data.
    #[error("embedded preset settings group is incomplete or duplicated")]
    InvalidGroup,
    /// A requested or declared group id does not exist.
    #[error("unknown preset settings group: {id}")]
    UnknownGroup {
        /// Unknown group id.
        id: String,
    },
}

/// Stateless selector for the embedded settings groups.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct SettingsGroupEngine;

impl SettingsGroupEngine {
    /// Validates and returns the embedded selector.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError`] when the embedded group table is malformed.
    #[inline]
    pub fn embedded() -> Result<Self, GroupError> {
        embedded_groups().map(|_groups| Self)
    }

    /// Returns all embedded group definitions in document order.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError`] when the embedded group table is malformed.
    #[inline]
    #[expect(
        clippy::unused_self,
        reason = "the validated engine value is the group capability"
    )]
    pub fn groups(self) -> Result<&'static [SettingsGroup], GroupError> {
        embedded_groups()
    }

    /// Selects source lines and closes group and referenced-line dependencies.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::UnknownGroup`] for an unknown selected or dependent group id.
    #[inline]
    #[expect(
        clippy::unused_self,
        reason = "the validated engine value is the group capability"
    )]
    pub fn select(self, source: &Ast, selected: &[&str]) -> Result<GroupSelection, GroupError> {
        let groups = embedded_groups()?;
        let by_id = groups
            .iter()
            .map(|group| (group.id.as_str(), group))
            .collect();
        let selected_groups = selection::close_group_dependencies(selected, &by_id)?;
        let lines = flatten(source);
        let mut included = selection::matching_line_indices(&lines, &selected_groups, &by_id);
        selection::close_line_dependencies(&lines, &selected_groups, &by_id, &mut included);
        Ok(GroupSelection {
            groups: selected_groups.into_iter().map(str::to_owned).collect(),
            lines: lines
                .into_iter()
                .enumerate()
                .filter_map(|(index, line)| included.contains(&index).then_some(line))
                .collect(),
        })
    }

    /// Reports whether a group pattern has a corresponding catalog command path.
    #[inline]
    #[must_use]
    pub fn pattern_matches_catalog(pattern: &str, path: &str) -> bool {
        glob::matches_catalog(pattern, path)
    }
}

/// Deserialized settings-group document.
#[derive(Deserialize)]
struct GroupDocument {
    /// Ordered settings groups.
    group: Vec<SettingsGroup>,
}

/// Parses and validates the compile-time group document once.
///
/// # Errors
///
/// Returns [`GroupError`] when the embedded TOML is malformed or incomplete.
fn embedded_groups() -> Result<&'static [SettingsGroup], GroupError> {
    static GROUPS: LazyLock<Result<Vec<SettingsGroup>, GroupError>> = LazyLock::new(|| {
        let document: GroupDocument =
            toml::from_str(GROUPS_TOML).map_err(|_error| GroupError::InvalidToml)?;
        let mut ids = BTreeSet::new();
        if document.group.iter().any(|group| {
            group.id.trim().is_empty()
                || group.title_key.trim().is_empty()
                || group.include.is_empty()
                || group
                    .include
                    .iter()
                    .any(|pattern| pattern.trim().is_empty())
                || !ids.insert(group.id.as_str())
        }) {
            return Err(GroupError::InvalidGroup);
        }
        Ok(document.group)
    });
    GROUPS.as_deref().map_err(Clone::clone)
}
