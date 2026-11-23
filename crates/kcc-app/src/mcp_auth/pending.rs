//! Authorization requests awaiting consent and the codes issued for them, in memory only.
//!
//! A request lives [`REQUEST_LIFETIME_SECONDS`] and is taken once (approve or deny). A code
//! lives [`CODE_LIFETIME_SECONDS`], is redeemed once (a refused attempt consumes it too)
//! and only with its own client, redirect URI, resource and PKCE S256 verifier. Request
//! ids and codes are kept as SHA-256 digests, found by a constant-time scan of every
//! entry; at most [`MAX_ENTRIES`] of each are held. When the requests are full, the
//! oldest request of the source (client address group) holding the most gives way, and
//! one source holds at most [`MAX_ENTRIES_PER_SOURCE`]; the oldest code gives way.

pub mod source;
mod store;

extern crate alloc;

use alloc::sync::Arc;
use core::ops::RangeInclusive;
use std::sync::Mutex;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};

use super::{RandomError, clients::Client, same};
use crate::accounts::Clock;

/// Seconds a pending authorization request can be taken.
pub const REQUEST_LIFETIME_SECONDS: u64 = 600;
/// Seconds an authorization code can be redeemed.
pub const CODE_LIFETIME_SECONDS: u64 = 60;
/// Most requests, and most codes, held at once.
pub const MAX_ENTRIES: usize = 1024;
/// Most requests one source (an address, or an IPv6 /64) holds at once.
pub const MAX_ENTRIES_PER_SOURCE: usize = 16;
/// Longest `state`, in characters.
const MAX_STATE_CHARS: usize = 512;
/// Length of an S256 challenge.
const CHALLENGE_CHARS: usize = 43;
/// Shortest and longest code verifier (RFC 7636 4.1).
const VERIFIER_CHARS: RangeInclusive<usize> = 43..=128;

/// A refused authorization request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "callers name it beside the other mcp_auth errors"
)]
pub enum PendingError {
    /// The method is not `S256` or the challenge is not 43 base64url characters.
    #[error("unsupported code challenge")]
    Challenge,
    /// The request names another client than the one given.
    #[error("the request names another client")]
    Client,
    /// The redirect URI is not registered for the client.
    #[error("the redirect URI is not registered")]
    RedirectUri,
    /// `state` is over 512 characters or holds a control or non-ASCII character.
    #[error("invalid state")]
    State,
    /// The OS random number generator failed.
    #[error(transparent)]
    Random(#[from] RandomError),
}

/// Why a code is refused. Every refusal answers `invalid_grant`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CodeRefusal {
    /// No such code, or it was used.
    #[error("unknown code")]
    Unknown,
    /// Redeemed [`CODE_LIFETIME_SECONDS`] or more after its issue.
    #[error("expired code")]
    Expired,
    /// Issued to another client.
    #[error("code of another client")]
    Client,
    /// Issued for another redirect URI.
    #[error("code for another redirect URI")]
    RedirectUri,
    /// Issued for another resource.
    #[error("code for another resource")]
    Resource,
    /// The verifier does not match the S256 challenge.
    #[error("wrong code verifier")]
    Verifier,
}

/// A PKCE S256 challenge: 43 base64url characters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PkceChallenge(String);

impl PkceChallenge {
    /// The challenge `challenge` sent with `code_challenge_method` `method`.
    ///
    /// # Errors
    ///
    /// [`PendingError::Challenge`] for any method but `S256` (`plain` included) or a
    /// challenge that is not 43 base64url characters.
    #[inline]
    pub fn parse(method: &str, challenge: &str) -> Result<Self, PendingError> {
        let shaped = challenge.len() == CHALLENGE_CHARS
            && challenge
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
        if method == "S256" && shaped {
            Ok(Self(challenge.to_owned()))
        } else {
            Err(PendingError::Challenge)
        }
    }

    /// The challenge text.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `verifier` is 43 to 128 unreserved characters whose S256 is the challenge.
    fn verifies(&self, verifier: &SecretString) -> bool {
        let text = verifier.expose_secret();
        let shaped = VERIFIER_CHARS.contains(&text.len())
            && text.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
            });
        let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes()));
        shaped & same(computed.as_bytes(), self.0.as_bytes())
    }
}

/// What a code is bound to: the client, the redirect URI and the resource.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeTarget {
    /// `client_id`.
    client_id: String,
    /// `redirect_uri`, as requested.
    redirect_uri: String,
    /// `resource` (RFC 8707).
    resource: String,
}

impl CodeTarget {
    /// The target `client_id`, `redirect_uri`, `resource`.
    #[inline]
    #[must_use]
    pub fn new(client_id: &str, redirect_uri: &str, resource: &str) -> Self {
        Self {
            client_id: client_id.to_owned(),
            redirect_uri: redirect_uri.to_owned(),
            resource: resource.to_owned(),
        }
    }

    /// The client id.
    #[inline]
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The redirect URI.
    #[inline]
    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// The resource.
    #[inline]
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }
}

/// A validated authorization request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthorizationRequest {
    /// Client, redirect URI and resource.
    target: CodeTarget,
    /// The PKCE challenge.
    challenge: PkceChallenge,
    /// The client's opaque `state`, echoed in the redirect.
    state: Option<String>,
}

impl AuthorizationRequest {
    /// A request for `target` on `client`, whose redirect URI must be registered for it.
    ///
    /// # Errors
    ///
    /// [`PendingError::Client`] when `target` names another client,
    /// [`PendingError::RedirectUri`] when its redirect URI does not match.
    #[inline]
    pub fn new(
        client: &Client,
        target: CodeTarget,
        challenge: PkceChallenge,
    ) -> Result<Self, PendingError> {
        if target.client_id != client.id() {
            return Err(PendingError::Client);
        }
        if !client.redirect_matches(&target.redirect_uri) {
            return Err(PendingError::RedirectUri);
        }
        Ok(Self {
            target,
            challenge,
            state: None,
        })
    }

    /// The same request carrying the client's `state`.
    ///
    /// # Errors
    ///
    /// [`PendingError::State`] for over 512 characters or one outside `0x20..=0x7e`.
    #[inline]
    pub fn with_state(mut self, state: Option<&str>) -> Result<Self, PendingError> {
        if let Some(text) = state
            && (text.len() > MAX_STATE_CHARS
                || !text.bytes().all(|byte| (0x20..=0x7e).contains(&byte)))
        {
            return Err(PendingError::State);
        }
        self.state = state.map(str::to_owned);
        Ok(self)
    }

    /// The client id.
    #[inline]
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.target.client_id
    }

    /// The redirect URI.
    #[inline]
    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.target.redirect_uri
    }

    /// The resource.
    #[inline]
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.target.resource
    }

    /// The client's `state`.
    #[inline]
    #[must_use]
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }
}

/// A redeemed code: who consented, for which client and resource.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthorizedCode {
    /// The consenting account.
    account: String,
    /// What the code was bound to.
    target: CodeTarget,
}

impl AuthorizedCode {
    /// The consenting account.
    #[inline]
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// The client id.
    #[inline]
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.target.client_id
    }

    /// The resource.
    #[inline]
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.target.resource
    }
}

/// One held entry: a request or an issued code.
struct Entry {
    /// SHA-256 of the request id or the code.
    digest: [u8; 32],
    /// When it was created, Unix seconds.
    created_at: u64,
    /// The request.
    request: AuthorizationRequest,
    /// The consenting account, for a code.
    account: Option<String>,
    /// The keyed hash of the requesting address group, for a request.
    source: Option<[u8; 32]>,
}

/// The held requests and codes.
#[derive(Default)]
struct Entries {
    /// Requests awaiting consent, oldest first.
    requests: Vec<Entry>,
    /// Issued codes, oldest first.
    codes: Vec<Entry>,
}

/// Pending requests and codes. `Debug` shows how many it holds.
#[expect(
    clippy::module_name_repetitions,
    reason = "the store name the authorization server uses"
)]
pub struct PendingStore {
    /// Clock of the lifetimes.
    clock: Arc<dyn Clock>,
    /// The entries.
    entries: Mutex<Entries>,
}
