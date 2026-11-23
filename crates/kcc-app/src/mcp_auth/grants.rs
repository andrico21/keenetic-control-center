//! Refresh grants in `mcp_oauth_grants.json`: one grant (token family) per consented
//! connection of an account and a client to a resource.
//!
//! A refresh token is never stored: the grant keeps the SHA-256 of the current one and of
//! up to [`MAX_PREVIOUS`] rotated ones. Each refresh rotates the token and restarts its
//! lifetime; presenting a rotated token again is reuse (RFC 9700 4.14.2) and revokes the
//! whole family. A grant also keeps a hash of the account's password fingerprint, so a
//! password change ends it. An account holds at most [`MAX_GRANTS_PER_ACCOUNT`] live
//! grants and the state at most [`MAX_GRANTS`]; revoked and expired grants are purged.

mod store;

extern crate alloc;

use alloc::{collections::BTreeSet, sync::Arc};
use core::{fmt, time::Duration};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{RandomError, hex, same};
use crate::{
    accounts::{Clock, standing::PasswordFingerprint},
    persist::{Migration, StateDoc, StateError, StateStore},
};

/// Most live grants of one account.
pub const MAX_GRANTS_PER_ACCOUNT: usize = 20;
/// Most live grants in total.
pub const MAX_GRANTS: usize = 500;
/// Rotated refresh token hashes kept per grant for reuse detection.
pub const MAX_PREVIOUS: usize = 16;
/// Domain separation of the stored password fingerprint hash.
const PASSWORD_CONTEXT: &[u8] = b"kcc mcp grant password fingerprint\0";

/// A refused or failed grant operation. Never carries a token.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GrantError {
    /// The code's client is no longer registered.
    #[error("unknown client")]
    UnknownClient,
    /// The account holds [`MAX_GRANTS_PER_ACCOUNT`] live grants.
    #[error("the account holds too many grants")]
    AccountLimit,
    /// [`MAX_GRANTS`] live grants are stored.
    #[error("too many grants are stored")]
    TotalLimit,
    /// No grant holds this refresh token.
    #[error("unknown refresh token")]
    Unknown,
    /// The refresh token expired.
    #[error("expired refresh token")]
    Expired,
    /// The grant was revoked.
    #[error("revoked grant")]
    Revoked,
    /// A rotated refresh token was presented again; the family is now revoked.
    #[error("reused refresh token; the grant is revoked")]
    Reused,
    /// The refresh token belongs to another client.
    #[error("refresh token of another client")]
    Client,
    /// The refresh asked for another resource.
    #[error("refresh for another resource")]
    Resource,
    /// The account may not sign in now, or its password changed.
    #[error("the account no longer holds this grant")]
    Account,
    /// State locking or filesystem persistence failed.
    #[error("grant storage failed")]
    State(#[from] StateError),
    /// The OS random number generator failed.
    #[error(transparent)]
    Random(#[from] RandomError),
}

/// The refresh token state of a grant: hashes only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Refresh {
    /// SHA-256 hex of the current token.
    current: String,
    /// When the current token expires, Unix seconds (exclusive).
    expires_at: u64,
    /// SHA-256 hex of rotated tokens, oldest first.
    previous: Vec<String>,
}

/// One grant. `Debug` leaves out the token and password hashes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Grant {
    /// Grant (family) id, 64 lowercase hex digits; the `kcc_grant` claim.
    id: String,
    /// The consenting account.
    account: String,
    /// The client.
    client: String,
    /// The canonical resource.
    resource: String,
    /// Creation time, Unix seconds.
    created_at: u64,
    /// Time of the last token issue, Unix seconds.
    last_used_at: u64,
    /// Hash of the account's password fingerprint at consent.
    password: String,
    /// Revoked by reuse, the client or an admin.
    revoked: bool,
    /// Refresh token hashes.
    refresh: Refresh,
}

impl fmt::Debug for Grant {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Grant")
            .field("id", &self.id)
            .field("account", &self.account)
            .field("client", &self.client)
            .field("resource", &self.resource)
            .field("created_at", &self.created_at)
            .field("last_used_at", &self.last_used_at)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

impl Grant {
    /// The grant id.
    #[inline]
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The consenting account.
    #[inline]
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// The client id.
    #[inline]
    #[must_use]
    pub fn client(&self) -> &str {
        &self.client
    }

    /// The canonical resource.
    #[inline]
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Creation time, Unix seconds.
    #[inline]
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Time of the last token issue, Unix seconds.
    #[inline]
    #[must_use]
    pub const fn last_used_at(&self) -> u64 {
        self.last_used_at
    }

    /// When the current refresh token expires, Unix seconds (exclusive).
    #[inline]
    #[must_use]
    pub const fn refresh_expires_at(&self) -> u64 {
        self.refresh.expires_at
    }

    /// Whether the grant was revoked.
    #[inline]
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Whether `fingerprint` is the password fingerprint the grant was made with.
    pub(crate) fn password_matches(&self, fingerprint: &PasswordFingerprint) -> bool {
        same(
            self.password.as_bytes(),
            password_hash(fingerprint).as_bytes(),
        )
    }
}

/// `mcp_oauth_grants.json`: every stored grant.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the state document name the plan and the docs use"
)]
pub struct GrantsDocument {
    /// The grants, oldest first.
    grants: Vec<Grant>,
}

impl StateDoc for GrantsDocument {
    const FILE_NAME: &'static str = "mcp_oauth_grants.json";
    const SCHEMA: u32 = 1;
    const MIGRATIONS: &'static [Migration] = &[];
}

/// Where a presented refresh token's hash was found.
enum Located {
    /// Nowhere.
    Absent,
    /// The current token of the grant at this index.
    Current(usize),
    /// A rotated token of the grant at this index.
    Previous(usize),
}

impl GrantsDocument {
    /// Every grant, oldest first.
    #[inline]
    #[must_use]
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    /// The grant `id`.
    #[inline]
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Grant> {
        self.grants.iter().find(|grant| grant.id == id)
    }

    /// The clients holding a grant that is neither revoked nor expired at `now`.
    pub(crate) fn live_clients(&self, now: u64) -> BTreeSet<String> {
        self.grants
            .iter()
            .filter(|grant| is_live(grant, now))
            .map(|grant| grant.client.clone())
            .collect()
    }

    /// Drops revoked and expired grants; answers whether any was dropped.
    fn purge(&mut self, now: u64) -> bool {
        let before = self.grants.len();
        self.grants.retain(|grant| is_live(grant, now));
        self.grants.len() != before
    }

    /// Finds `digest` among every grant's current and rotated hashes, comparing each in
    /// constant time.
    fn locate(&self, digest: &str) -> Located {
        let wanted = digest.as_bytes();
        self.grants
            .iter()
            .enumerate()
            .fold(Located::Absent, |found, (index, grant)| {
                let rotated = grant
                    .refresh
                    .previous
                    .iter()
                    .fold(false, |hit, old| hit | same(old.as_bytes(), wanted));
                if same(grant.refresh.current.as_bytes(), wanted) {
                    Located::Current(index)
                } else if rotated {
                    Located::Previous(index)
                } else {
                    found
                }
            })
    }
}

/// Whether `grant` is neither revoked nor expired at `now`.
const fn is_live(grant: &Grant, now: u64) -> bool {
    !grant.revoked && now < grant.refresh.expires_at
}

/// The stored form of `fingerprint`: SHA-256 hex over a context label and its bytes.
fn password_hash(fingerprint: &PasswordFingerprint) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PASSWORD_CONTEXT);
    hasher.update(fingerprint.as_bytes());
    hex(&hasher.finalize())
}

/// A grant and its new refresh token, handed to the client once.
#[derive(Debug)]
#[non_exhaustive]
pub struct IssuedGrant {
    /// The grant as stored.
    grant: Grant,
    /// The refresh token.
    refresh: SecretString,
}

impl IssuedGrant {
    /// The grant as stored.
    #[inline]
    #[must_use]
    pub const fn grant(&self) -> &Grant {
        &self.grant
    }

    /// The refresh token.
    #[inline]
    #[must_use]
    pub const fn refresh_token(&self) -> &SecretString {
        &self.refresh
    }
}

/// A refresh token request (RFC 6749 6, RFC 8707 2.2).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RefreshRequest<'request> {
    /// The presented refresh token.
    token: &'request SecretString,
    /// The presenting client.
    client_id: &'request str,
    /// The resource asked for, if any.
    resource: Option<&'request str>,
}

impl<'request> RefreshRequest<'request> {
    /// `token` presented by `client_id`, optionally for `resource`.
    #[inline]
    #[must_use]
    pub const fn new(
        token: &'request SecretString,
        client_id: &'request str,
        resource: Option<&'request str>,
    ) -> Self {
        Self {
            token,
            client_id,
            resource,
        }
    }
}

/// Stores, rotates and revokes grants.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GrantStore {
    /// State root holding the grants and clients.
    state: StateStore,
    /// Clock of every time stamp and expiry.
    clock: Arc<dyn Clock>,
    /// Lifetime of each refresh token.
    refresh_ttl: Duration,
}
