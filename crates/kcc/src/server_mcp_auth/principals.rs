//! The accounts and grants behind kcc account tokens.
//!
//! `users.json`, `mcp_oauth_grants.json` and `mcp_oauth_clients.json` are read again
//! whenever they changed on disk (inode, modification time, size), which is checked on
//! every call: a change binds the next call. A grant whose client is no longer registered
//! authorizes nothing.

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::fmt;
use std::sync::{Mutex, PoisonError};

use kcc_app::{
    accounts::{AccountStore, standing::AccountStanding},
    mcp_auth::{
        clients::ClientsDocument,
        grants::GrantsDocument,
        verify::{GrantRefusal, check_grant},
    },
    persist::{StateDoc, StateStore},
};
use kcc_mcp::principals::{McpPrincipals, PrincipalRefusal};

use crate::state_watch::{Version, observe};

/// The accounts file.
const USERS: &str = "users.json";

/// What the last calls read, with the file versions they read.
#[derive(Default)]
struct Cache {
    /// Every account's standing.
    users: Option<(Version, BTreeMap<String, AccountStanding>)>,
    /// The grants.
    grants: Option<(Version, GrantsDocument)>,
    /// The registered clients.
    clients: Option<(Version, ClientsDocument)>,
}

/// [`McpPrincipals`] over the state directory.
pub(crate) struct FilePrincipals {
    /// The accounts.
    accounts: Arc<AccountStore>,
    /// The state directory.
    state: StateStore,
    /// The files as last read.
    cache: Mutex<Cache>,
}

impl fmt::Debug for FilePrincipals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FilePrincipals").finish_non_exhaustive()
    }
}

impl FilePrincipals {
    /// The principals of `accounts`, the grants in `state`.
    pub(crate) fn new(accounts: Arc<AccountStore>, state: StateStore) -> Self {
        Self {
            accounts,
            state,
            cache: Mutex::new(Cache::default()),
        }
    }
}

impl McpPrincipals for FilePrincipals {
    fn resolve(&self, account: &str, grant: &str) -> Result<String, PrincipalRefusal> {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let users_now = observe(&self.state.dir().join(USERS));
        if cache
            .users
            .as_ref()
            .is_none_or(|(read, _)| *read != users_now)
        {
            let standings = self.accounts.standings().map_err(|error| {
                tracing::warn!(%error, "the accounts cannot be read for a kcc token");
                PrincipalRefusal::Unavailable
            })?;
            cache.users = Some((users_now, standings));
        }
        refreshed(&self.state, &mut cache.grants, "grants")?;
        refreshed(&self.state, &mut cache.clients, "clients")?;
        let decided = decide(&cache, account, grant);
        drop(cache);
        decided
    }
}

/// Reads `T` into `slot` again when its file changed since; `what` names it in the log.
///
/// # Errors
///
/// [`PrincipalRefusal::Unavailable`] when the file cannot be read or parsed.
fn refreshed<T>(
    state: &StateStore,
    slot: &mut Option<(Version, T)>,
    what: &'static str,
) -> Result<(), PrincipalRefusal>
where
    T: StateDoc,
{
    let now = observe(&state.dir().join(T::FILE_NAME));
    if slot.as_ref().is_none_or(|(read, _)| *read != now) {
        let document = state
            .read::<T>()
            .map_err(|error| {
                tracing::warn!(%error, what, "a state file cannot be read for a kcc token");
                PrincipalRefusal::Unavailable
            })?
            .unwrap_or_default();
        *slot = Some((now, document));
    }
    Ok(())
}

/// The role `account` holds now when it, `grant` and the grant's client stand in `cache`.
///
/// # Errors
///
/// [`PrincipalRefusal`] naming the first check that failed.
fn decide(cache: &Cache, account: &str, grant: &str) -> Result<String, PrincipalRefusal> {
    let (Some((_, users)), Some((_, grants)), Some((_, clients))) =
        (&cache.users, &cache.grants, &cache.clients)
    else {
        return Err(PrincipalRefusal::Unavailable);
    };
    let standing = users
        .get(account)
        .filter(|standing| !standing.disabled && !standing.must_change_password)
        .ok_or(PrincipalRefusal::Account)?;
    let fingerprint = standing.fingerprint.ok_or(PrincipalRefusal::Account)?;
    check_grant(grants, grant, account, &fingerprint).map_err(|refusal| match refusal {
        GrantRefusal::Unknown | GrantRefusal::Revoked => PrincipalRefusal::Grant,
        GrantRefusal::Account | GrantRefusal::Password | _ => PrincipalRefusal::Account,
    })?;
    let granted = grants.get(grant).ok_or(PrincipalRefusal::Grant)?;
    if clients.client(granted.client()).is_none() {
        return Err(PrincipalRefusal::Grant);
    }
    Ok(standing.role.clone())
}
