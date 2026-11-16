//! Cached read-only polling clients, one per router id.

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{mem, time::Duration};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kcc_rci::RciClient;
use tokio::{runtime, sync::OnceCell, task::JoinSet, time::timeout};

/// The lazily built read-only client of one router id.
type Slot = Arc<OnceCell<Arc<RciClient>>>;

/// Longest wait for a router to acknowledge the sign-out of one read-only session.
const LOGOUT_BOUND: Duration = Duration::from_secs(5);

/// Read-only clients and the flag that ends their use at shutdown.
#[derive(Debug, Default)]
pub(super) struct ReadPool {
    /// One slot per router id; a slot is built outside the map lock.
    state: Mutex<State>,
}

/// Slots and whether the pool still hands them out.
#[derive(Debug, Default)]
struct State {
    /// Slots by router id.
    slots: BTreeMap<String, Slot>,
    /// Set once shutdown took the slots.
    closed: bool,
}

impl ReadPool {
    /// Locks the state; the sections are short and never await, so a poisoned lock holds
    /// consistent data.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The slot of `id`, or `None` once the pool is shut down.
    pub(super) fn slot(&self, id: &str) -> Option<Slot> {
        let mut state = self.state();
        if state.closed {
            return None;
        }
        Some(Arc::clone(state.slots.entry(id.to_owned()).or_default()))
    }

    /// Drops the cached client of `id` and signs its session out in the background.
    pub(super) fn forget(&self, id: &str) {
        let removed = self.state().slots.remove(id);
        if let Some(client) = removed.as_deref().and_then(OnceCell::get).map(Arc::clone)
            && let Ok(runtime) = runtime::Handle::try_current()
        {
            drop(runtime.spawn(async move {
                drop(timeout(LOGOUT_BOUND, client.logout()).await);
            }));
        }
    }

    /// Ends the pool: signs every cached session out concurrently, each within
    /// [`LOGOUT_BOUND`], and refuses new clients from now on.
    // NOT cancel-safe: cancelled midway, some sessions stay open on their routers.
    pub(super) async fn close(&self) {
        let slots = {
            let mut state = self.state();
            state.closed = true;
            mem::take(&mut state.slots)
        };
        let mut logouts = JoinSet::new();
        for client in slots.values().filter_map(|slot| slot.get().map(Arc::clone)) {
            drop(logouts.spawn(async move {
                if timeout(LOGOUT_BOUND, client.logout()).await.is_err() {
                    tracing::warn!("read-only router session sign-out timed out");
                }
            }));
        }
        while logouts.join_next().await.is_some() {}
    }
}
