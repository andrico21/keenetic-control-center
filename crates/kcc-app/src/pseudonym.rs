//! One-way client pseudonyms: a keyed hash with a per-process random key.
//!
//! Nothing is stored per client, so the memory is independent of how many distinct
//! identifiers were seen. The key lives in this process only and is never logged or
//! serialized: a pseudonym is stable while the process runs and different after a restart.

use core::hash::BuildHasher as _;
use std::{collections::hash_map::RandomState, sync::OnceLock};

/// The process-wide key (`SipHash` with a random 128-bit key).
fn key() -> &'static RandomState {
    static KEY: OnceLock<RandomState> = OnceLock::new();
    KEY.get_or_init(RandomState::new)
}

/// The pseudonym of `identifier` inside `scope`: `client-` and 16 lowercase hex digits.
///
/// The same identifier gives the same pseudonym within one scope and one process run (case
/// is ignored); a different scope gives an unrelated one.
#[must_use]
#[inline]
pub fn client(scope: &str, identifier: &str) -> String {
    let hash = key().hash_one((scope, identifier.to_ascii_lowercase()));
    format!("client-{hash:016x}")
}

#[cfg(test)]
#[expect(clippy::missing_panics_doc, reason = "test code fails by panicking")]
mod tests {
    use super::client;

    /// Same scope and identifier agree (ignoring case); another scope or identifier differs.
    #[test]
    fn pseudonyms_are_stable_per_scope_and_one_way_shaped() {
        let pseudonym = client("router-1", "02:00:00:00:00:01");
        assert_eq!(pseudonym, client("router-1", "02:00:00:00:00:01"));
        assert_eq!(
            client("router-1", "02:00:00:00:00:0A"),
            client("router-1", "02:00:00:00:00:0a")
        );
        assert_ne!(pseudonym, client("router-2", "02:00:00:00:00:01"));
        assert_ne!(pseudonym, client("router-1", "02:00:00:00:00:02"));
        assert_eq!(pseudonym.len(), "client-".len() + 16);
        assert!(!pseudonym.contains("02:00"));
    }
}
