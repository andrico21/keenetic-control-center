//! Throttled "last used" recording for MCP API keys.
//!
//! Every authenticated MCP request could rewrite `api_keys.json`; [`KeyUseRecorder`]
//! lets at most one write through per key every [`KEY_USE_INTERVAL`] seconds, so the
//! keys page stays accurate to the minute without churning the state file.

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::fmt;
use std::sync::{Mutex, PoisonError};

use crate::{
    accounts::Clock,
    api_keys::record_api_key_use,
    persist::{StateError, StateStore},
};

/// Shortest time between two recorded uses of one key, in seconds.
pub const KEY_USE_INTERVAL: u64 = 60;

/// Decides when a key's use is worth recording and records it.
#[non_exhaustive]
pub struct KeyUseRecorder {
    /// State directory holding `api_keys.json`.
    store: StateStore,
    /// Time source of the recorded uses.
    clock: Arc<dyn Clock>,
    /// The last recorded use of each key, in Unix seconds.
    recorded: Mutex<BTreeMap<String, u64>>,
}

impl fmt::Debug for KeyUseRecorder {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyUseRecorder")
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

/// One use of a key that is due to be written.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "a due use is recorded only by `KeyUse::persist`"]
pub struct KeyUse {
    /// State directory holding `api_keys.json`.
    store: StateStore,
    /// Key name.
    name: String,
    /// Unix seconds of the use.
    at: u64,
}

impl KeyUse {
    /// Writes the use to `api_keys.json` (blocking file I/O); `false` when the key no
    /// longer exists.
    ///
    /// # Errors
    ///
    /// A state error when `api_keys.json` cannot be read or written.
    #[inline]
    pub fn persist(self) -> Result<bool, StateError> {
        record_api_key_use(&self.store, &self.name, self.at)
    }
}

impl KeyUseRecorder {
    /// A recorder writing to `store` at times from `clock`.
    #[inline]
    #[must_use]
    pub fn new(store: StateStore, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            clock,
            recorded: Mutex::new(BTreeMap::new()),
        }
    }

    /// Notes a successful authentication with the key `name`: the use to write when the
    /// key's last recorded use is at least [`KEY_USE_INTERVAL`] old, otherwise `None`.
    #[inline]
    pub fn note(&self, name: &str) -> Option<KeyUse> {
        let now = self.clock.unix_seconds();
        let mut recorded = self.recorded.lock().unwrap_or_else(PoisonError::into_inner);
        let due = recorded
            .get(name)
            .is_none_or(|last| now.saturating_sub(*last) >= KEY_USE_INTERVAL);
        if !due {
            return None;
        }
        let _previous: Option<u64> = recorded.insert(name.to_owned(), now);
        drop(recorded);
        Some(KeyUse {
            store: self.store.clone(),
            name: name.to_owned(),
            at: now,
        })
    }
}
