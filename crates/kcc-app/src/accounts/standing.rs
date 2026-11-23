//! What a signed-in Web session depends on in its account: the role, whether login is
//! disabled, and a fingerprint of the password hash.

extern crate alloc;

use alloc::collections::BTreeMap;
use core::fmt;

use secrecy::ExposeSecret as _;
use sha2::{Digest as _, Sha256};

use super::{Account, AccountError, AccountStore, UsersDocument};
use crate::secrets::binding::Binding;

/// SHA-256 of an account's opened PHC string. It changes exactly when the password
/// changes, lives only in memory, and its `Debug` output shows nothing of it.
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PasswordFingerprint([u8; 32]);

impl fmt::Debug for PasswordFingerprint {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordFingerprint(<redacted>)")
    }
}

impl PasswordFingerprint {
    /// The fingerprint of the PHC string `phc`.
    pub(super) fn of(phc: &str) -> Self {
        Self(Sha256::digest(phc.as_bytes()).into())
    }

    /// The fingerprint's bytes, from which the MCP grants derive the value they store.
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One account as its signed-in sessions see it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "callers name it beside `AccountStore` and `AccountSummary`"
)]
pub struct AccountStanding {
    /// Granted role name.
    pub role: String,
    /// Whether login is administratively disabled.
    pub disabled: bool,
    /// Whether the account must choose a new password before anything else.
    pub must_change_password: bool,
    /// The password's fingerprint; `None` when the stored hash cannot be opened, which
    /// no session matches.
    pub fingerprint: Option<PasswordFingerprint>,
}

/// Every account's standing, keyed by username.
///
/// # Errors
///
/// A state error when `users.json` cannot be read or parsed.
pub(super) fn all(store: &AccountStore) -> Result<BTreeMap<String, AccountStanding>, AccountError> {
    let document = store.state.read::<UsersDocument>()?.unwrap_or_default();
    Ok(document
        .users
        .iter()
        .map(|account| {
            let standing = AccountStanding {
                role: account.role.clone(),
                disabled: account.disabled,
                must_change_password: account.must_change_password,
                fingerprint: opened(store, account),
            };
            (account.username.clone(), standing)
        })
        .collect())
}

/// The fingerprint of `username`'s password; `None` when there is no such account or
/// its hash cannot be opened.
///
/// # Errors
///
/// A state error when `users.json` cannot be read or parsed.
pub(super) fn of_account(
    store: &AccountStore,
    username: &str,
) -> Result<Option<PasswordFingerprint>, AccountError> {
    let document = store.state.read::<UsersDocument>()?.unwrap_or_default();
    Ok(document
        .users
        .iter()
        .find(|account| account.username == username)
        .and_then(|account| opened(store, account)))
}

/// The fingerprint of `account`'s stored hash; `None` when it cannot be opened, so the
/// account's sessions end rather than survive on a hash nobody can check.
fn opened(store: &AccountStore, account: &Account) -> Option<PasswordFingerprint> {
    store
        .key
        .open(&Binding::account(&account.username), &account.password_hash)
        .ok()
        .map(|phc| PasswordFingerprint::of(phc.expose_secret()))
}
