//! Role assignment: the `roles.json` lock, the role lookup and the dominance check.
//!
//! Lock order for every writer of role holders: `roles.json`, then `users.json`, then
//! `api_keys.json`. An assignment holds the roles lock while it writes the holder, and a
//! role deletion holds all three while it counts holders and removes the role, so neither
//! can slip between the other's check and write.

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};

use super::{PermissionError, Role, RolesDocument, load_roles};
use crate::{
    accounts::UsersDocument,
    api_keys::ApiKeysDocument,
    persist::{StateDoc as _, StateError, StateLock, StateStore},
};

#[cfg(test)]
mod tests;

/// Why a role cannot be assigned.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GrantError {
    /// The roles could not be loaded.
    #[error(transparent)]
    Roles(#[from] PermissionError),
    /// No built-in or custom role has this name.
    #[error("role {name:?} is not configured")]
    UnknownRole {
        /// The requested role name.
        name: String,
    },
    /// The acting role does not hold every permission or router of the granted role.
    #[error("the acting role does not cover the granted role")]
    Forbidden,
}

/// A role being assigned, with `roles.json` locked until this value is dropped.
#[derive(Debug)]
pub(crate) struct RoleGrant {
    /// The held `roles.json` lock.
    _lock: StateLock,
}

impl RoleGrant {
    /// Locks `roles.json` and requires the role `name` to exist.
    ///
    /// # Errors
    ///
    /// [`GrantError::UnknownRole`], or a lock or roles-loading failure.
    pub(crate) fn existing(store: &StateStore, name: &str) -> Result<Self, GrantError> {
        Self::checked(store, name, |_role| true)
    }

    /// Locks `roles.json` and requires the role `name` to exist and `actor` to dominate it.
    ///
    /// # Errors
    ///
    /// [`GrantError::Forbidden`], as [`Self::existing`].
    pub(crate) fn by(store: &StateStore, actor: &Role, name: &str) -> Result<Self, GrantError> {
        Self::checked(store, name, |role| actor.dominates(role))
    }

    /// Locks `roles.json`, finds `name` and requires `allowed` of it.
    ///
    /// # Errors
    ///
    /// As [`Self::by`].
    fn checked<F>(store: &StateStore, name: &str, allowed: F) -> Result<Self, GrantError>
    where
        F: FnOnce(&Role) -> bool,
    {
        #[cfg(test)]
        probe::emit(probe::Step::Locking);
        let lock = store
            .lock(RolesDocument::FILE_NAME)
            .map_err(PermissionError::from)?;
        let roles = load_roles(store)?;
        let role =
            roles
                .iter()
                .find(|role| role.name == name)
                .ok_or_else(|| GrantError::UnknownRole {
                    name: name.to_owned(),
                })?;
        if !allowed(role) {
            return Err(GrantError::Forbidden);
        }
        Ok(Self { _lock: lock })
    }
}

/// Removes the role `name` from `roles` unless an account, an API key or the MCP
/// settings (`mcp_held`, see `McpBase::held_roles`) hold it, and answers whether it was
/// removed.
///
/// `roles` is the document [`StateStore::update`] holds under the `roles.json` lock; the
/// holders are counted under the `users.json` and `api_keys.json` locks, taken in that
/// order, so no assignment can add a holder between the count and the removal. A saved MCP
/// settings change takes the `roles.json` lock too, so `mcp_held` read under that lock
/// stays true until the removal.
///
/// # Errors
///
/// A lock or read failure of `users.json` or `api_keys.json`.
#[inline]
pub fn remove_unheld(
    store: &StateStore,
    roles: &mut RolesDocument,
    name: &str,
    mcp_held: &BTreeSet<String>,
) -> Result<bool, StateError> {
    let _users = store.lock(UsersDocument::FILE_NAME)?;
    let _keys = store.lock(ApiKeysDocument::FILE_NAME)?;
    let held = holder_counts(store, mcp_held)?
        .get(name)
        .is_some_and(|count| *count > 0);
    #[cfg(test)]
    probe::emit(probe::Step::Counted);
    if held {
        return Ok(false);
    }
    roles.roles.retain(|role| role.name != name);
    Ok(true)
}

/// How many accounts, API keys and MCP settings hold each role; each role of `mcp_held`
/// counts once.
///
/// # Errors
///
/// A state error while reading `users.json` or `api_keys.json`.
#[inline]
pub fn holder_counts(
    store: &StateStore,
    mcp_held: &BTreeSet<String>,
) -> Result<BTreeMap<String, usize>, StateError> {
    let accounts = store.read::<UsersDocument>()?.unwrap_or_default().users;
    let keys = store.read::<ApiKeysDocument>()?.unwrap_or_default().keys;
    let mut counts = BTreeMap::new();
    for role in accounts
        .into_iter()
        .map(|account| account.role)
        .chain(keys.into_iter().map(|key| key.role))
        .chain(mcp_held.iter().cloned())
    {
        let count: &mut usize = counts.entry(role).or_default();
        *count = count.saturating_add(1);
    }
    Ok(counts)
}

/// A per-thread observer of role assignments and deletions, so tests can hold one up.
#[cfg(test)]
pub(crate) mod probe {
    extern crate alloc;

    use alloc::rc::Rc;
    use core::cell::RefCell;

    /// A point an assignment or deletion passes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Step {
        /// An assignment is about to wait for the `roles.json` lock.
        Locking,
        /// A deletion counted the role's holders and has not removed it yet.
        Counted,
    }

    /// Called at every step of the current thread.
    pub(crate) type Observer = Rc<dyn Fn(Step)>;

    thread_local! {
        /// The observer of the current thread.
        static PROBE: RefCell<Option<Observer>> = const { RefCell::new(None) };
    }

    /// Calls `observer` at every step of the current thread.
    pub(crate) fn install(observer: Observer) {
        PROBE.with_borrow_mut(|slot| *slot = Some(observer));
    }

    /// Reports `step` to the current thread's observer, if any.
    pub(super) fn emit(step: Step) {
        if let Some(observer) = PROBE.with_borrow(Clone::clone) {
            observer(step);
        }
    }
}
