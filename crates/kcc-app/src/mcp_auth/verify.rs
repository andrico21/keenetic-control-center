//! What a resource server needs on every MCP call with a kcc token: the grant id of a token
//! the kit already verified, and the check that the grant still authorizes its account.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;
use zeroize::Zeroizing;

use super::{grants::GrantsDocument, is_id};
use crate::accounts::standing::PasswordFingerprint;

/// Longest token [`grant_id`] reads, in bytes.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// Why a grant no longer authorizes a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GrantRefusal {
    /// No such grant (never issued, or purged after revocation or expiry).
    #[error("unknown grant")]
    Unknown,
    /// The grant was revoked.
    #[error("revoked grant")]
    Revoked,
    /// The grant belongs to another account.
    #[error("grant of another account")]
    Account,
    /// The account's password changed since the grant was made.
    #[error("the password changed")]
    Password,
}

/// Whether grant `grant_id` of `grants` still authorizes `account`, whose current password
/// has `fingerprint`. The account's enabled state is the caller's check.
///
/// # Errors
///
/// The first [`GrantRefusal`] in the order unknown, revoked, account, password.
#[inline]
pub fn check_grant(
    grants: &GrantsDocument,
    grant_id: &str,
    account: &str,
    fingerprint: &PasswordFingerprint,
) -> Result<(), GrantRefusal> {
    let grant = grants.get(grant_id).ok_or(GrantRefusal::Unknown)?;
    if grant.is_revoked() {
        return Err(GrantRefusal::Revoked);
    }
    if grant.account() != account {
        return Err(GrantRefusal::Account);
    }
    if !grant.password_matches(fingerprint) {
        return Err(GrantRefusal::Password);
    }
    Ok(())
}

/// The `kcc_grant` claim of the compact JWS `token`, which the caller has already verified.
///
/// `None` for anything but three dot-separated parts of at most [`MAX_TOKEN_BYTES`] whose
/// middle part is unpadded base64url of a JSON object with a `kcc_grant` string of 64
/// lowercase hex digits.
#[inline]
#[must_use]
pub fn grant_id(token: &SecretString) -> Option<String> {
    let text = token.expose_secret();
    if text.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let mut parts = text.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(payload).ok()?);
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    let grant = claims.get("kcc_grant")?.as_str()?;
    is_id(grant).then(|| grant.to_owned())
}
