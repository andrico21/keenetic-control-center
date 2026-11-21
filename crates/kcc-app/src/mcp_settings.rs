//! The effective MCP settings: kcc.toml, its `[mcp] locked` keys, the environment and
//! the Web-managed `mcp_settings.json`.
//!
//! Precedence per key: a `KCC_MCP_*` variable, then a kcc.toml value whose key
//! `[mcp] locked` names, then `mcp_settings.json`, then kcc.toml, then the default. kcc.toml,
//! its locks and the environment are read at start ([`McpBase`]); the state file is read
//! each time.
//!
//! A change is planned first ([`McpBase::plan_update`], [`McpBase::reset`]), which checks
//! everything and writes nothing, and then saved with [`commit`]. A save takes the
//! `roles.json` lock and then the `mcp_settings.json` lock, and is refused with
//! [`SettingsError::SettingsChanged`] when another save came between plan and commit.

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};

use crate::{
    mcp_settings::{
        document::{McpOverrides, McpSettingsDocument},
        keys::KeyPath,
    },
    permissions::{PermissionError, Role, RolesDocument},
    persist::{Edit, StateDoc as _, StateError, StateStore},
    settings::{
        Config, ConfigError, McpConfig, OverrideReport,
        mcp_schema::{self, named_roles},
    },
};

pub mod document;
pub mod keys;
mod update;

/// Where an effective value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Source {
    /// A `KCC_MCP_*` environment variable.
    Env,
    /// kcc.toml, and `[mcp] locked` names the key.
    Locked,
    /// `mcp_settings.json`, set on the Web.
    State,
    /// kcc.toml.
    Toml,
    /// The built-in default.
    Default,
}

/// An MCP listener a change restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ListenerKind {
    /// The main listener, which also serves the Web UI.
    Main,
    /// The dedicated MCP listener.
    Dedicated,
}

/// The `[mcp]` keys the environment set at start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct EnvOverrides {
    /// Keys set by a `KCC_MCP_*` variable.
    keys: BTreeSet<KeyPath>,
}

impl EnvOverrides {
    /// The `[mcp]` keys of the report [`Config::apply_env_overrides`] returned.
    #[inline]
    #[must_use]
    pub fn from_reports(reports: &[OverrideReport]) -> Self {
        Self {
            keys: reports
                .iter()
                .filter_map(|report| report.target_field.strip_prefix("mcp.")?.parse().ok())
                .collect(),
        }
    }

    /// Whether the environment set `key`.
    #[inline]
    #[must_use]
    pub fn contains(&self, key: KeyPath) -> bool {
        self.keys.contains(&key)
    }
}

/// Why the MCP settings cannot be resolved or changed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SettingsError {
    /// `mcp_settings.json` or another state file failed.
    #[error(transparent)]
    State(#[from] StateError),
    /// The roles could not be loaded.
    #[error(transparent)]
    Roles(#[from] PermissionError),
    /// The resulting settings break a `[mcp]` rule.
    #[error(transparent)]
    Invalid(#[from] ConfigError),
    /// An environment variable sets the key.
    #[error("{key} is set by an environment variable")]
    EnvSet {
        /// The refused key.
        key: KeyPath,
    },
    /// `[mcp] locked` names the key.
    #[error("{key} is locked in kcc.toml")]
    Locked {
        /// The refused key.
        key: KeyPath,
    },
    /// No toolset has this name.
    #[error("unknown toolset {name:?}")]
    UnknownToolset {
        /// The refused name.
        name: String,
    },
    /// No built-in or custom role has this name.
    #[error("role {name:?} is not configured")]
    UnknownRole {
        /// The refused name.
        name: String,
    },
    /// The acting role does not hold every permission or router of the named role.
    #[error("role {name:?} is above the acting role")]
    RoleAbove {
        /// The refused name.
        name: String,
    },
    /// The acting role is no longer configured or no longer holds `ManageMcp`.
    #[error("the acting role {name:?} no longer manages the MCP settings")]
    ActorRevoked {
        /// The acting role's name.
        name: String,
    },
    /// `mcp_settings.json` changed after the change was planned.
    #[error("the MCP settings changed since this change was planned")]
    SettingsChanged,
    /// The revision of `mcp_settings.json` is at its maximum, so no further change can be
    /// told apart from it.
    #[error("the MCP settings revision cannot grow any further")]
    RevisionExhausted,
}

/// The effective settings with the source of each Web-managed key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Effective {
    /// The values `kcc serve` and `kcc mcp stdio` use.
    mcp: McpConfig,
    /// Source per key.
    sources: BTreeMap<KeyPath, Source>,
}

impl Effective {
    /// The values `kcc serve` and `kcc mcp stdio` use.
    #[inline]
    #[must_use]
    pub const fn settings(&self) -> &McpConfig {
        &self.mcp
    }

    /// The values, without the sources.
    #[inline]
    #[must_use]
    pub fn into_settings(self) -> McpConfig {
        self.mcp
    }

    /// Where the value of `key` comes from.
    #[inline]
    #[must_use]
    pub fn source(&self, key: KeyPath) -> Source {
        self.sources.get(&key).copied().unwrap_or(Source::Default)
    }
}

/// A planned change: the document to write and what it does. Nothing is written until
/// [`commit`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Candidate {
    /// The document [`commit`] writes.
    document: McpSettingsDocument,
    /// The revision the change was planned on.
    base_version: u64,
    /// The settings after the change.
    effective: Effective,
    /// Keys whose effective value changes.
    changed: Vec<KeyPath>,
    /// Changed keys that reduce safety.
    safety_reducing: Vec<KeyPath>,
    /// Listeners the change restarts.
    restart: Vec<ListenerKind>,
    /// The acting role and the roles it must still cover at commit.
    ceiling: update::Ceiling,
}

impl Candidate {
    /// The document [`commit`] writes.
    #[inline]
    #[must_use]
    pub const fn document(&self) -> &McpSettingsDocument {
        &self.document
    }

    /// The `mcp_settings.json` revision the change was planned on.
    #[inline]
    #[must_use]
    pub const fn base_version(&self) -> u64 {
        self.base_version
    }

    /// The settings after the change.
    #[inline]
    #[must_use]
    pub const fn effective(&self) -> &Effective {
        &self.effective
    }

    /// Keys whose effective value changes, in [`KeyPath::ALL`] order.
    #[inline]
    #[must_use]
    pub fn changed(&self) -> &[KeyPath] {
        &self.changed
    }

    /// Changed keys that reduce safety (the Web asks for the password again).
    #[inline]
    #[must_use]
    pub fn safety_reducing(&self) -> &[KeyPath] {
        &self.safety_reducing
    }

    /// Listeners the change restarts.
    #[inline]
    #[must_use]
    pub fn restart(&self) -> &[ListenerKind] {
        &self.restart
    }
}

/// kcc.toml's `[mcp]` and the environment, as read at start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct McpBase {
    /// `[mcp]` after the environment overrides.
    mcp: McpConfig,
    /// Keys kcc.toml sets (or whose value is not the default).
    toml: BTreeSet<KeyPath>,
    /// Keys `[mcp] locked` names.
    locked: BTreeSet<KeyPath>,
    /// Keys the environment set.
    env: EnvOverrides,
}

impl McpBase {
    /// Captures `config`'s `[mcp]` (environment overrides applied) and `env`.
    #[inline]
    #[must_use]
    pub fn new(config: &Config, env: &EnvOverrides) -> Self {
        let defaults = McpConfig::default();
        Self {
            toml: KeyPath::ALL
                .iter()
                .copied()
                .filter(|key| {
                    config.sets_mcp_key(key.as_str()) || keys::differs(&config.mcp, &defaults, *key)
                })
                .collect(),
            locked: config
                .mcp
                .locked
                .iter()
                .filter_map(|key| key.parse().ok())
                .collect(),
            mcp: config.mcp.clone(),
            env: env.clone(),
        }
    }

    /// The effective settings with `mcp_settings.json` of `store`.
    ///
    /// # Errors
    ///
    /// [`SettingsError::State`] for an unreadable file, [`SettingsError::Invalid`] when
    /// the result breaks a `[mcp]` rule.
    #[inline]
    pub fn effective(&self, store: &StateStore) -> Result<Effective, SettingsError> {
        let document = store.read::<McpSettingsDocument>()?.unwrap_or_default();
        self.resolve(&document.overrides)
    }

    /// Every role kcc.toml or `mcp_settings.json` names as the stdio role, the mTLS role
    /// or an OIDC mapping target; such a role cannot be deleted.
    ///
    /// # Errors
    ///
    /// [`SettingsError::State`] for an unreadable file.
    #[inline]
    pub fn held_roles(&self, store: &StateStore) -> Result<BTreeSet<String>, SettingsError> {
        let document = store.read::<McpSettingsDocument>()?.unwrap_or_default();
        let mut with_state = self.mcp.clone();
        for key in KeyPath::ALL {
            keys::overlay(&document.overrides, *key, &mut with_state);
        }
        let mut held = named_roles(&self.mcp);
        held.extend(named_roles(&with_state));
        Ok(held)
    }

    /// Plans setting every key `change` sets, as `actor`, without writing anything.
    /// `toolsets` answers, per toolset name, `None` for an unknown toolset and otherwise
    /// whether turning it on reduces safety.
    ///
    /// `actor` is checked by name against the current role definitions, here and again at
    /// [`commit`].
    ///
    /// # Errors
    ///
    /// [`SettingsError::ActorRevoked`] when the current definition of `actor` is missing or
    /// lacks `ManageMcp`, [`SettingsError::EnvSet`], [`SettingsError::Locked`],
    /// [`SettingsError::UnknownToolset`], [`SettingsError::UnknownRole`],
    /// [`SettingsError::RoleAbove`], [`SettingsError::Invalid`],
    /// [`SettingsError::RevisionExhausted`], or a state failure.
    #[inline]
    pub fn plan_update(
        &self,
        store: &StateStore,
        actor: &Role,
        change: &McpOverrides,
        toolsets: &dyn Fn(&str) -> Option<bool>,
    ) -> Result<Candidate, SettingsError> {
        update::plan(
            self,
            store,
            update::Request::Set { actor, change },
            toolsets,
        )
    }

    /// Plans removing `key` from `mcp_settings.json`, as `actor`, so kcc.toml or the
    /// default applies again, without writing anything.
    ///
    /// # Errors
    ///
    /// [`SettingsError::ActorRevoked`] as for [`McpBase::plan_update`],
    /// [`SettingsError::UnknownRole`] or [`SettingsError::RoleAbove`] when the value that
    /// applies again names a role for a new purpose that is missing or above `actor`,
    /// [`SettingsError::Invalid`], [`SettingsError::RevisionExhausted`], or a state
    /// failure.
    #[inline]
    pub fn reset(
        &self,
        store: &StateStore,
        actor: &Role,
        key: KeyPath,
    ) -> Result<Candidate, SettingsError> {
        update::plan(
            self,
            store,
            update::Request::Reset { actor, key },
            &|_name| Some(false),
        )
    }

    /// Resolves the settings with `overrides` as the state file's values.
    ///
    /// # Errors
    ///
    /// [`SettingsError::Invalid`] when the result breaks a `[mcp]` rule.
    fn resolve(&self, overrides: &McpOverrides) -> Result<Effective, SettingsError> {
        let mut mcp = self.mcp.clone();
        let mut sources = BTreeMap::new();
        for key in KeyPath::ALL.iter().copied() {
            let source = if self.env.contains(key) {
                Source::Env
            } else if self.locked.contains(&key) {
                Source::Locked
            } else if keys::is_set(overrides, key) {
                keys::overlay(overrides, key, &mut mcp);
                Source::State
            } else if self.toml.contains(&key) {
                Source::Toml
            } else {
                Source::Default
            };
            let _: Option<Source> = sources.insert(key, source);
        }
        mcp_schema::checks::validate(&mcp)?;
        Ok(Effective { mcp, sources })
    }
}

/// The effective MCP settings of `config` (environment overrides applied), the keys `env`
/// set, and `mcp_settings.json` of `store`.
///
/// # Errors
///
/// As [`McpBase::effective`].
#[inline]
pub fn effective(
    config: &Config,
    env: &EnvOverrides,
    store: &StateStore,
) -> Result<Effective, SettingsError> {
    McpBase::new(config, env).effective(store)
}

/// Writes `candidate`'s document unless the settings or the roles changed against it.
///
/// It is refused when `mcp_settings.json` changed since it was planned, the acting role's
/// current definition is missing or lacks `ManageMcp`, or a role it names is gone or now
/// above the acting role's current definition.
///
/// # Errors
///
/// [`SettingsError::SettingsChanged`], [`SettingsError::ActorRevoked`],
/// [`SettingsError::UnknownRole`],
/// [`SettingsError::RoleAbove`], or a state failure.
#[inline]
pub fn commit(store: &StateStore, candidate: &Candidate) -> Result<(), SettingsError> {
    let _roles = store.lock(RolesDocument::FILE_NAME)?;
    store.update_if_changed(|document: &mut McpSettingsDocument| {
        if document.revision != candidate.base_version {
            return Edit::Unchanged(Err(SettingsError::SettingsChanged));
        }
        if let Err(error) = candidate.ceiling.check(store) {
            return Edit::Unchanged(Err(error));
        }
        document.clone_from(&candidate.document);
        Edit::Changed(Ok(()))
    })?
}
