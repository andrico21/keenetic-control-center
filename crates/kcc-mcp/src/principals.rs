//! Who a kcc account token speaks for, decided again on every call.
//!
//! A token kcc issued names an account (`sub`) and a grant (`kcc_grant`); the kit has
//! verified its signature, issuer, audience and expiry. [`McpPrincipals`] says whether the
//! grant and the account still stand and which role the account holds now, so a role
//! change, a disabled account, a changed password or a revoked grant binds the next call.

use core::fmt;

/// Why a kcc token does not authorize a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrincipalRefusal {
    /// The grant is unknown, revoked or belongs to another account.
    Grant,
    /// The account is gone, disabled, must change its password, or its password changed
    /// since the grant was issued.
    Account,
    /// The token names no account or grant, or the accounts or grants could not be read.
    Unavailable,
}

impl fmt::Display for PrincipalRefusal {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Grant => "the grant is unknown or revoked",
            Self::Account => "the account cannot sign in or its password changed",
            Self::Unavailable => "the account or the grant could not be read",
        })
    }
}

/// Resolves the account behind a kcc access token at the time of a call.
#[expect(
    clippy::module_name_repetitions,
    reason = "the name the binary and the Web UI use for this seam"
)]
pub trait McpPrincipals: fmt::Debug + Send + Sync {
    /// The role name `account` holds now, when the grant `grant` is live and belongs to
    /// it, the account exists, is enabled, need not change its password, and has the
    /// password the grant was issued with.
    ///
    /// Blocking: it may read the state files.
    ///
    /// # Errors
    ///
    /// [`PrincipalRefusal`] naming the first check that failed.
    fn resolve(&self, account: &str, grant: &str) -> Result<String, PrincipalRefusal>;
}
