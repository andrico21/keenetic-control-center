//! What the notifier remembers so that a message goes out once.
//!
//! Lockouts are remembered per account and window, in memory only; the firmware version
//! announced per router is kept in `notify_state.json`, so a restart does not announce it
//! again.

extern crate alloc;

use alloc::collections::BTreeMap;

use kcc_app::{
    notify_store::NotifyRuntime,
    persist::{StateError, StateStore},
};

/// Accounts whose latest lockout is remembered; beyond that the oldest name is forgotten.
const MAX_ACCOUNTS: usize = 1024;

/// The latest lockout window reported per account.
#[derive(Debug, Default)]
pub(super) struct Lockouts {
    /// Username to the end of its reported window, in Unix seconds.
    reported: BTreeMap<String, u64>,
}

impl Lockouts {
    /// Whether the lockout of `user` until `until` is not reported yet; records it.
    pub(super) fn first(&mut self, user: &str, until: u64) -> bool {
        if self.reported.get(user) == Some(&until) {
            return false;
        }
        if !self.reported.contains_key(user) && self.reported.len() >= MAX_ACCOUNTS {
            drop(self.reported.pop_first());
        }
        let _: Option<u64> = self.reported.insert(user.to_owned(), until);
        true
    }
}

/// The firmware version announced per router.
#[derive(Debug, Default)]
pub(super) struct Firmware {
    /// Router id to the latest announced version.
    announced: BTreeMap<String, String>,
}

impl Firmware {
    /// The versions `notify_state.json` records.
    ///
    /// # Errors
    ///
    /// A state read failure.
    pub(super) fn load(state: &StateStore) -> Result<Self, StateError> {
        Ok(Self {
            announced: state
                .read::<NotifyRuntime>()?
                .unwrap_or_default()
                .firmware_notified,
        })
    }

    /// Whether `version` was not announced for `router` yet; remembers it.
    pub(super) fn offer(&mut self, router: &str, version: &str) -> bool {
        if self.announced.get(router).map(String::as_str) == Some(version) {
            return false;
        }
        drop(self.announced.insert(router.to_owned(), version.to_owned()));
        true
    }
}

/// Records in `notify_state.json` that `version` was announced for `router`.
///
/// # Errors
///
/// A state write failure.
pub(super) fn record(
    state: &StateStore,
    router: String,
    version: String,
) -> Result<(), StateError> {
    state.update(|runtime: &mut NotifyRuntime| {
        drop(runtime.firmware_notified.insert(router, version));
    })
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::error::Error;

    use kcc_app::persist::StateStore;
    use tempfile::TempDir;

    use super::{Firmware, Lockouts, record};

    /// Todo 10: one lockout window of an account is reported once; a new window, or
    /// another account, is reported again.
    #[test]
    fn a_lockout_is_reported_once_per_window() {
        let mut lockouts = Lockouts::default();
        assert!(lockouts.first("bob", 900), "first window");
        assert!(!lockouts.first("bob", 900), "same window again");
        assert!(lockouts.first("alice", 900), "another account");
        assert!(lockouts.first("bob", 1900), "a later window");
    }

    /// Todo 10: a firmware version is announced once per router, also across a restart
    /// that reloads `notify_state.json`; a newer version is announced again.
    #[test]
    fn firmware_is_announced_once_per_version_across_a_restart() -> Result<(), Box<dyn Error>> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let mut running = Firmware::load(&state)?;
        assert!(running.offer("home", "5.1.9"), "first sighting");
        record(&state, "home".to_owned(), "5.1.9".to_owned())?;
        assert!(!running.offer("home", "5.1.9"), "same process");

        let mut restarted = Firmware::load(&state)?;

        assert!(!restarted.offer("home", "5.1.9"), "after a restart");
        assert!(restarted.offer("office", "5.1.9"), "another router");
        assert!(restarted.offer("home", "5.2.0"), "a newer version");
        Ok(())
    }
}
