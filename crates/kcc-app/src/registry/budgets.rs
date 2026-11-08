//! Router-id admission budgets that survive client cache replacement.

extern crate alloc;

use alloc::collections::BTreeMap;

use kcc_rci::budget::Budget;
use tokio::sync::Mutex;

/// Keeps one budget per router id for the registry's lifetime.
#[derive(Debug, Default)]
pub(super) struct Budgets {
    /// Entries remain while older client handles may still be used.
    entries: Mutex<BTreeMap<String, Budget>>,
}

impl Budgets {
    /// Returns the existing budget or allocates its first two slots.
    // cancel-safe: cancellation before locking changes nothing; insertion is synchronous.
    pub(super) async fn get(&self, id: &str) -> Budget {
        self.entries
            .lock()
            .await
            .entry(id.to_owned())
            .or_default()
            .clone()
    }
}
