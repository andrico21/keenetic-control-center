//! What a session knows of its account, and why sessions could not be checked against
//! the accounts.

use kcc_app::{
    accounts::{AccountError, standing::PasswordFingerprint},
    permissions::Role,
};
use tokio::task::JoinError;

/// The account a session signs in as.
#[derive(Debug)]
pub(crate) struct SignedIn {
    /// Login name.
    username: String,
    /// Resolved role.
    role: Role,
    /// Fingerprint of the password read before the sign-in was checked.
    fingerprint: Option<PasswordFingerprint>,
}

impl SignedIn {
    /// `username` holding `role`, whose password had `fingerprint` before the sign-in
    /// was checked.
    pub(crate) const fn new(
        username: String,
        role: Role,
        fingerprint: Option<PasswordFingerprint>,
    ) -> Self {
        Self {
            username,
            role,
            fingerprint,
        }
    }

    /// The login name, role and fingerprint.
    pub(crate) fn into_parts(self) -> (String, Role, Option<PasswordFingerprint>) {
        (self.username, self.role, self.fingerprint)
    }
}

/// Why the sessions could not be checked against the accounts. No session ended.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StandingsError {
    /// `users.json` cannot be read or parsed.
    #[error(transparent)]
    Accounts(#[from] AccountError),
    /// The blocking read did not complete.
    #[error("account read did not complete: {0}")]
    Task(#[from] JoinError),
}
