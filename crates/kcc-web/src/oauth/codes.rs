//! The password each authorization code was consented with, so that a code redeemed after
//! a password change (up to a minute later) issues nothing.
//!
//! Memory only, keyed by the code's SHA-256: no code is kept.

extern crate alloc;

use alloc::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use kcc_app::{
    accounts::standing::PasswordFingerprint,
    mcp_auth::pending::{CODE_LIFETIME_SECONDS, MAX_ENTRIES},
};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};

/// The consenting password per issued code.
#[derive(Default)]
pub(crate) struct Consented {
    /// Code digest -> (password fingerprint, Unix second it was consented).
    codes: Mutex<BTreeMap<[u8; 32], (PasswordFingerprint, u64)>>,
}

impl Consented {
    /// Records that `code` was consented at `now` with the password `fingerprint`.
    pub(crate) fn record(&self, code: &SecretString, fingerprint: PasswordFingerprint, now: u64) {
        let mut codes = self.codes.lock().unwrap_or_else(PoisonError::into_inner);
        codes.retain(|_digest, (_fingerprint, at)| now < at.saturating_add(CODE_LIFETIME_SECONDS));
        if codes.len() >= MAX_ENTRIES
            && let Some(oldest) = codes
                .iter()
                .min_by_key(|(_digest, (_fingerprint, at))| *at)
                .map(|(digest, _consent)| *digest)
        {
            let _: Option<(PasswordFingerprint, u64)> = codes.remove(&oldest);
        }
        let _: Option<(PasswordFingerprint, u64)> = codes.insert(digest(code), (fingerprint, now));
    }

    /// The password `code` was consented with, forgetting it; `None` for a code this
    /// process did not issue.
    pub(crate) fn take(&self, code: &SecretString) -> Option<PasswordFingerprint> {
        self.codes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&digest(code))
            .map(|(fingerprint, _at)| fingerprint)
    }
}

/// The SHA-256 of `code`.
fn digest(code: &SecretString) -> [u8; 32] {
    Sha256::digest(code.expose_secret().as_bytes()).into()
}
