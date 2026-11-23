//! The store operations and the entry bookkeeping.

extern crate alloc;

use alloc::sync::Arc;
use core::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};

use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};

use super::{
    AuthorizationRequest, AuthorizedCode, CODE_LIFETIME_SECONDS, CodeRefusal, CodeTarget, Entries,
    Entry, MAX_ENTRIES, PendingError, PendingStore, REQUEST_LIFETIME_SECONDS,
};
use crate::{
    accounts::Clock,
    mcp_auth::{new_secret, same},
};

impl fmt::Debug for PendingStore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.lock();
        f.debug_struct("PendingStore")
            .field("requests", &entries.requests.len())
            .field("codes", &entries.codes.len())
            .finish_non_exhaustive()
    }
}

impl PendingStore {
    /// An empty store on `clock`.
    #[inline]
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            entries: Mutex::new(Entries::default()),
        }
    }

    /// Holds `request` and answers its id (256 random bits, 43 base64url characters).
    ///
    /// # Errors
    ///
    /// [`PendingError::Random`] when the OS RNG fails.
    #[inline]
    pub fn begin(&self, request: AuthorizationRequest) -> Result<SecretString, PendingError> {
        let id = new_secret()?;
        let now = self.clock.unix_seconds();
        let entry = Entry {
            digest: digest(&id),
            created_at: now,
            request,
            account: None,
        };
        hold(
            &mut self.lock().requests,
            entry,
            now,
            REQUEST_LIFETIME_SECONDS,
        );
        Ok(id)
    }

    /// The live request `id`, left in place (the consent page shows it).
    #[inline]
    #[must_use]
    pub fn peek(&self, id: &str) -> Option<AuthorizationRequest> {
        let now = self.clock.unix_seconds();
        let entries = self.lock();
        let index = find(&entries.requests, &digest_of(id))?;
        entries
            .requests
            .get(index)
            .filter(|entry| live(entry, now, REQUEST_LIFETIME_SECONDS))
            .map(|entry| entry.request.clone())
    }

    /// Removes and answers the live request `id`: a request is approved or denied once.
    #[inline]
    #[must_use]
    pub fn take(&self, id: &str) -> Option<AuthorizationRequest> {
        let now = self.clock.unix_seconds();
        let entry = {
            let mut entries = self.lock();
            let index = find(&entries.requests, &digest_of(id))?;
            entries.requests.remove(index)
        };
        live(&entry, now, REQUEST_LIFETIME_SECONDS).then_some(entry.request)
    }

    /// Issues a code for `request` approved by `account` (256 random bits, 43 base64url
    /// characters).
    ///
    /// # Errors
    ///
    /// [`PendingError::Random`] when the OS RNG fails.
    #[inline]
    pub fn issue_code(
        &self,
        request: AuthorizationRequest,
        account: &str,
    ) -> Result<SecretString, PendingError> {
        let code = new_secret()?;
        let now = self.clock.unix_seconds();
        let entry = Entry {
            digest: digest(&code),
            created_at: now,
            request,
            account: Some(account.to_owned()),
        };
        hold(&mut self.lock().codes, entry, now, CODE_LIFETIME_SECONDS);
        Ok(code)
    }

    /// Redeems `code` for `target` with `verifier`. The code is consumed whatever the
    /// outcome.
    ///
    /// # Errors
    ///
    /// The first [`CodeRefusal`] in the order unknown, expired, client, redirect URI,
    /// resource, verifier.
    #[inline]
    pub fn redeem(
        &self,
        code: &SecretString,
        target: &CodeTarget,
        verifier: &SecretString,
    ) -> Result<AuthorizedCode, CodeRefusal> {
        let now = self.clock.unix_seconds();
        let entry = {
            let mut entries = self.lock();
            let index = find(&entries.codes, &digest(code)).ok_or(CodeRefusal::Unknown)?;
            entries.codes.remove(index)
        };
        let bound = &entry.request.target;
        if !live(&entry, now, CODE_LIFETIME_SECONDS) {
            return Err(CodeRefusal::Expired);
        }
        if bound.client_id != target.client_id {
            return Err(CodeRefusal::Client);
        }
        if bound.redirect_uri != target.redirect_uri {
            return Err(CodeRefusal::RedirectUri);
        }
        if bound.resource != target.resource {
            return Err(CodeRefusal::Resource);
        }
        if !entry.request.challenge.verifies(verifier) {
            return Err(CodeRefusal::Verifier);
        }
        Ok(AuthorizedCode {
            account: entry.account.ok_or(CodeRefusal::Unknown)?,
            target: entry.request.target,
        })
    }

    /// The entries, even after a panic in another holder (they stay consistent: every
    /// change is one push or remove).
    fn lock(&self) -> MutexGuard<'_, Entries> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Adds `entry` to `held` after dropping the expired ones and, at [`MAX_ENTRIES`], the
/// oldest.
fn hold(held: &mut Vec<Entry>, entry: Entry, now: u64, lifetime: u64) {
    held.retain(|old| live(old, now, lifetime));
    if held.len() >= MAX_ENTRIES {
        drop(held.drain(..1));
    }
    held.push(entry);
}

/// Whether `entry` is still within `lifetime` seconds at `now`.
const fn live(entry: &Entry, now: u64, lifetime: u64) -> bool {
    now < entry.created_at.saturating_add(lifetime)
}

/// The position of the entry with `digest`, comparing every entry in constant time.
fn find(held: &[Entry], digest: &[u8; 32]) -> Option<usize> {
    held.iter().enumerate().fold(None, |found, (index, entry)| {
        if same(&entry.digest, digest) {
            Some(index)
        } else {
            found
        }
    })
}

/// SHA-256 of a secret.
fn digest(secret: &SecretString) -> [u8; 32] {
    digest_of(secret.expose_secret())
}

/// SHA-256 of `text`.
fn digest_of(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}
