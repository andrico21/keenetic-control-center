//! Planning a change: refusals, the role ceiling, and what the change does.

extern crate alloc;

use alloc::collections::BTreeSet;
use core::iter;

use super::{
    Candidate, ListenerKind, McpBase, SettingsError,
    document::{McpOverrides, McpSettingsDocument},
    keys::{self, KeyPath},
};
use crate::{
    permissions::{Permission, Role, load_roles},
    persist::StateStore,
    settings::{
        McpConfig,
        mcp_schema::{DedicatedTls, ListenerAuth, MtlsMode, OauthMode},
    },
};

/// What a plan does to the state file.
#[derive(Clone, Copy)]
pub(super) enum Request<'input> {
    /// Set every key `change` sets, as `actor`.
    Set {
        /// The acting role.
        actor: &'input Role,
        /// The new values.
        change: &'input McpOverrides,
    },
    /// Remove one key, as `actor`.
    Reset {
        /// The acting role.
        actor: &'input Role,
        /// The key to remove.
        key: KeyPath,
    },
}

/// The acting role and the roles a change names, checked again when it is saved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Ceiling {
    /// The acting role's name; its definition is read again at every check.
    actor: String,
    /// Roles the change names; each must exist.
    named: BTreeSet<String>,
    /// Roles the change names for a purpose they did not have; the actor must cover each.
    added: BTreeSet<String>,
}

impl Ceiling {
    /// Checks the acting role and the named roles against the current role definitions.
    ///
    /// # Errors
    ///
    /// [`SettingsError::ActorRevoked`], [`SettingsError::UnknownRole`],
    /// [`SettingsError::RoleAbove`] or a roles failure.
    pub(super) fn check(&self, store: &StateStore) -> Result<(), SettingsError> {
        let roles = load_roles(store)?;
        let actor = find(&roles, &self.actor)
            .filter(|actor| actor.grants(Permission::ManageMcp))
            .ok_or_else(|| SettingsError::ActorRevoked {
                name: self.actor.clone(),
            })?;
        for name in &self.named {
            let role = find(&roles, name)
                .ok_or_else(|| SettingsError::UnknownRole { name: name.clone() })?;
            if self.added.contains(name) && !actor.dominates(role) {
                return Err(SettingsError::RoleAbove { name: name.clone() });
            }
        }
        Ok(())
    }
}

/// Plans `request` on the current `mcp_settings.json` without writing it.
///
/// # Errors
///
/// As [`McpBase::plan_update`].
pub(super) fn plan(
    base: &McpBase,
    store: &StateStore,
    request: Request<'_>,
    toolsets: &dyn Fn(&str) -> Option<bool>,
) -> Result<Candidate, SettingsError> {
    let current = store.read::<McpSettingsDocument>()?.unwrap_or_default();
    let before = base.resolve(&current.overrides)?;
    let mut document = current.clone();
    document.revision = current
        .revision
        .checked_add(1)
        .ok_or(SettingsError::RevisionExhausted)?;
    let (actor, mut named) = match request {
        Request::Reset { actor, key } => {
            keys::clear(&mut document.overrides, key);
            (actor, BTreeSet::new())
        }
        Request::Set { actor, change } => {
            for key in KeyPath::ALL.iter().copied() {
                if !keys::is_set(change, key) {
                    continue;
                }
                if base.env.contains(key) {
                    return Err(SettingsError::EnvSet { key });
                }
                if base.locked.contains(&key) {
                    return Err(SettingsError::Locked { key });
                }
                keys::copy(change, key, &mut document.overrides);
            }
            if let Some(name) = change
                .toolsets
                .iter()
                .flatten()
                .find(|name| toolsets(name).is_none())
            {
                return Err(SettingsError::UnknownToolset { name: name.clone() });
            }
            (actor, change_roles(change))
        }
    };
    let after = base.resolve(&document.overrides)?;
    let added = added_roles(&before.mcp, &after.mcp);
    named.extend(added.iter().cloned());
    let ceiling = Ceiling {
        actor: actor.name.clone(),
        named,
        added,
    };
    ceiling.check(store)?;
    let roles = load_roles(store)?;
    let changed: Vec<KeyPath> = KeyPath::ALL
        .iter()
        .copied()
        .filter(|key| keys::differs(&before.mcp, &after.mcp, *key))
        .collect();
    let judge = Judge {
        old: &before.mcp,
        new: &after.mcp,
        roles: &roles,
        toolsets,
    };
    let safety_reducing = changed
        .iter()
        .copied()
        .filter(|key| judge.reduces_safety(*key))
        .collect();
    let restart = [ListenerKind::Main, ListenerKind::Dedicated]
        .into_iter()
        .filter(|listener| changed.iter().any(|key| judge.restarts(*key, *listener)))
        .collect();
    Ok(Candidate {
        document,
        base_version: current.revision,
        effective: after,
        changed,
        safety_reducing,
        restart,
        ceiling,
    })
}

/// The roles `change` names.
fn change_roles(change: &McpOverrides) -> BTreeSet<String> {
    let oidc = &change.auth.oidc;
    change
        .stdio_role
        .iter()
        .chain(&change.auth.mtls.default_role)
        .cloned()
        .chain(
            oidc.role_mappings
                .iter()
                .flatten()
                .map(|mapping| mapping.role.clone()),
        )
        .chain(
            oidc.scopes
                .iter()
                .flatten()
                .map(|mapping| mapping.role.clone()),
        )
        .collect()
}

/// The roles `after` names where `before` did not name them for the same purpose: a new
/// stdio or mTLS role, or a mapping (claim value or scope to role) `before` lacks.
fn added_roles(before: &McpConfig, after: &McpConfig) -> BTreeSet<String> {
    let (old, new) = (&before.auth.oidc, &after.auth.oidc);
    iter::once(&after.stdio_role)
        .filter(|role| **role != before.stdio_role)
        .chain(
            after
                .auth
                .mtls
                .default_role
                .iter()
                .filter(|role| before.auth.mtls.default_role.as_ref() != Some(*role)),
        )
        .chain(
            new.role_mappings
                .iter()
                .filter(|mapping| !old.role_mappings.contains(mapping))
                .map(|mapping| &mapping.role),
        )
        .chain(
            new.scopes
                .iter()
                .filter(|mapping| !old.scopes.contains(mapping))
                .map(|mapping| &mapping.role),
        )
        .cloned()
        .collect()
}

/// The role named `name`.
fn find<'roles>(roles: &'roles [Role], name: &str) -> Option<&'roles Role> {
    roles.iter().find(|role| role.name == name)
}

/// Compares the settings before and after a change.
struct Judge<'plan> {
    /// Before the change.
    old: &'plan McpConfig,
    /// After the change.
    new: &'plan McpConfig,
    /// The current roles.
    roles: &'plan [Role],
    /// Per toolset name: unknown, or whether it reduces safety.
    toolsets: &'plan dyn Fn(&str) -> Option<bool>,
}

impl Judge<'_> {
    /// Whether the change of `key` reduces safety.
    fn reduces_safety(&self, key: KeyPath) -> bool {
        let (old, new) = (self.old, self.new);
        match key {
            KeyPath::AllowDestructive => new.allow_destructive,
            KeyPath::ReadOnly => !new.read_only,
            KeyPath::StdioEnabled => new.stdio_enabled,
            KeyPath::Toolsets => new
                .toolsets
                .iter()
                .any(|name| !old.toolsets.contains(name) && (self.toolsets)(name).unwrap_or(true)),
            KeyPath::StdioRole => {
                match (
                    find(self.roles, &old.stdio_role),
                    find(self.roles, &new.stdio_role),
                ) {
                    (Some(before), Some(after)) => !before.dominates(after),
                    (None | Some(_), None) | (None, Some(_)) => true,
                }
            }
            KeyPath::MainOauth => new.auth.main.oauth != OauthMode::None,
            KeyPath::DedicatedOauth => new.auth.dedicated.oauth != OauthMode::None,
            KeyPath::MainMtls => mtls_loosened(old.auth.main.mtls, new.auth.main.mtls),
            KeyPath::DedicatedMtls => {
                mtls_loosened(old.auth.dedicated.mtls, new.auth.dedicated.mtls)
            }
            KeyPath::DedicatedEnabled | KeyPath::DedicatedBind => {
                new.dedicated.enabled && !new.dedicated.bind.is_loopback()
            }
            KeyPath::DedicatedTls => new.dedicated.tls == DedicatedTls::None,
            KeyPath::KccAccessTtl => new.auth.kcc.access_ttl > old.auth.kcc.access_ttl,
            KeyPath::KccRefreshTtl => new.auth.kcc.refresh_ttl > old.auth.kcc.refresh_ttl,
            KeyPath::OidcIssuer
            | KeyPath::OidcAudience
            | KeyPath::OidcJwksUri
            | KeyPath::OidcRoleClaim
            | KeyPath::OidcRoleMappings
            | KeyPath::OidcScopes
            | KeyPath::OidcAllowedAlgorithms
            | KeyPath::MtlsDefaultRole => true,
            KeyPath::HttpEnabled
            | KeyPath::MaxResultBytes
            | KeyPath::Endpoint
            | KeyPath::DedicatedPort
            | KeyPath::DedicatedPublicUrl => false,
        }
    }

    /// Whether the change of `key` restarts `listener`; the dedicated listener only when
    /// it runs before or after the change.
    fn restarts(&self, key: KeyPath, listener: ListenerKind) -> bool {
        let runs = match listener {
            ListenerKind::Main => true,
            ListenerKind::Dedicated => self.old.dedicated.enabled || self.new.dedicated.enabled,
        };
        let uses = |method: fn(ListenerAuth) -> bool| {
            [self.old, self.new].iter().any(|mcp| {
                method(match listener {
                    ListenerKind::Main => mcp.auth.main,
                    ListenerKind::Dedicated => mcp.auth.dedicated,
                })
            })
        };
        let affected = match key {
            KeyPath::HttpEnabled | KeyPath::Endpoint => true,
            KeyPath::MainOauth | KeyPath::MainMtls => listener == ListenerKind::Main,
            KeyPath::DedicatedEnabled
            | KeyPath::DedicatedBind
            | KeyPath::DedicatedPort
            | KeyPath::DedicatedPublicUrl
            | KeyPath::DedicatedTls
            | KeyPath::DedicatedOauth
            | KeyPath::DedicatedMtls => listener == ListenerKind::Dedicated,
            KeyPath::KccAccessTtl | KeyPath::KccRefreshTtl => {
                uses(|auth| auth.oauth == OauthMode::Kcc)
            }
            KeyPath::OidcIssuer
            | KeyPath::OidcAudience
            | KeyPath::OidcJwksUri
            | KeyPath::OidcRoleClaim
            | KeyPath::OidcRoleMappings
            | KeyPath::OidcScopes
            | KeyPath::OidcAllowedAlgorithms => uses(|auth| auth.oauth == OauthMode::External),
            KeyPath::MtlsDefaultRole => uses(|auth| auth.mtls != MtlsMode::Off),
            KeyPath::StdioEnabled
            | KeyPath::StdioRole
            | KeyPath::ReadOnly
            | KeyPath::AllowDestructive
            | KeyPath::MaxResultBytes
            | KeyPath::Toolsets => false,
        };
        runs && affected
    }
}

/// Whether going from `old` to `new` adds certificate sign-in or drops `required`.
fn mtls_loosened(old: MtlsMode, new: MtlsMode) -> bool {
    match new {
        MtlsMode::Off => false,
        MtlsMode::Optional => true,
        MtlsMode::Required => old == MtlsMode::Off,
    }
}
