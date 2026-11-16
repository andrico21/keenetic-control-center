//! A router id checked before it names a credential record, its lock or its binding.

use super::{CredentialError, CredentialKind};

/// A router id of 1..=32 bytes from `[a-z0-9-]`: a safe file-name component that holds
/// no `:`, so no id's binding can end like another id's binding of another kind.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RouterId<'id>(&'id str);

impl<'id> RouterId<'id> {
    /// Checks `router`.
    ///
    /// # Errors
    /// Returns [`CredentialError::Record`] for an id outside the rule.
    pub(crate) fn parse(router: &'id str) -> Result<Self, CredentialError> {
        let valid = (1..=32).contains(&router.len())
            && router
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        valid.then_some(Self(router)).ok_or(CredentialError::Record)
    }

    /// The id.
    pub(crate) const fn as_str(self) -> &'id str {
        self.0
    }

    /// The state-lock name of the router's credentials.
    pub(super) fn lock_name(self) -> String {
        format!("credential-{}", self.0)
    }

    /// The record file name of the router's credential of `kind`.
    pub(super) fn file_name(self, kind: CredentialKind) -> String {
        let router = self.0;
        match kind {
            CredentialKind::Password => format!("{router}.sealed"),
            CredentialKind::Token => format!("{router}.token.sealed"),
            CredentialKind::ReadPassword => format!("{router}.read.sealed"),
        }
    }

    /// The legacy plaintext password file name.
    pub(super) fn legacy_file_name(self) -> String {
        format!("{}.password", self.0)
    }
}
