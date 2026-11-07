//! The wizards' in-memory side.
//!
//! One request at a time per migration, and the analysis each migration works on (its
//! parsed source and the target's inventory), read from the routers once and kept while
//! the migration is open.
//!
//! Everything here can be rebuilt from the files (`store`) and the routers, so a restart
//! loses no choice: the next request reads the routers again.
//!
//! The presets' apply runs keep their own [`Wizards`]: the turns, the target's inventory
//! and the live apply work the same way for both wizards.

use alloc::{collections::BTreeMap, sync::Arc};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kcc_migrate::inventory::TargetInventory;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use super::{analysis::Analysis, live::Live};

/// Migrations kept in memory; the oldest one is forgotten first.
const KEPT: usize = 64;

/// The in-memory side of every open migration of one Web UI.
#[derive(Default)]
pub(crate) struct Wizards {
    /// Migration id and its session, oldest first.
    sessions: Mutex<Vec<(String, Arc<Session>)>>,
    /// Target router and the migration applying to it, until that one finishes.
    active: Mutex<BTreeMap<String, String>>,
}

impl Wizards {
    /// Reserves `target` for migration `id`; `false` when another migration holds it.
    pub(crate) fn claim(&self, target: &str, id: &str) -> bool {
        lock(&self.active)
            .entry(target.to_owned())
            .or_insert_with(|| id.to_owned())
            == id
    }

    /// Frees `target` when migration `id` holds it.
    pub(crate) fn release(&self, target: &str, id: &str) {
        let mut active = lock(&self.active);
        if active.get(target).is_some_and(|holder| holder == id) {
            drop(active.remove(target));
        }
    }

    /// The session of migration `id`, created on first use.
    pub(crate) fn session(&self, id: &str) -> Arc<Session> {
        let mut sessions = lock(&self.sessions);
        if let Some((_, found)) = sessions.iter().find(|(known, _)| known == id) {
            return Arc::clone(found);
        }
        if sessions.len() >= KEPT
            && let Some(idle) = sessions
                .iter()
                .position(|(_, session)| lock(&session.live).is_none())
        {
            drop(sessions.remove(idle));
        }
        let session = Arc::new(Session::default());
        sessions.push((id.to_owned(), Arc::clone(&session)));
        session
    }
}

/// One migration's in-memory side.
#[derive(Default)]
pub(crate) struct Session {
    /// Held by the request working on the migration, so two tabs never interleave.
    turn: Arc<AsyncMutex<()>>,
    /// The analysis of the current source and target, keyed by the target it read.
    analysis: Mutex<BTreeMap<String, Arc<Analysis>>>,
    /// A router's inventory, keyed by the router: a router source's own, for the maps, or
    /// a preset run's target.
    inventories: Mutex<BTreeMap<String, Arc<TargetInventory>>>,
    /// The apply, while kcc runs it and until it finishes.
    live: Mutex<Option<Arc<Live>>>,
}

impl Session {
    /// Waits for the migration's turn; requests on one migration run one at a time, and
    /// each reads the record only once it holds the turn.
    pub(crate) async fn turn(&self) -> OwnedMutexGuard<()> {
        Arc::clone(&self.turn).lock_owned().await
    }

    /// The kept analysis of `target`.
    pub(super) fn analysis(&self, target: &str) -> Option<Arc<Analysis>> {
        lock(&self.analysis).get(target).cloned()
    }

    /// Keeps `analysis` of `target`, replacing any other.
    pub(super) fn keep(&self, target: &str, analysis: Arc<Analysis>) {
        let mut kept = lock(&self.analysis);
        kept.clear();
        drop(kept.insert(target.to_owned(), analysis));
    }

    /// Forgets the kept analysis and inventories: the source or the target changed.
    pub(crate) fn forget(&self) {
        lock(&self.analysis).clear();
        lock(&self.inventories).clear();
    }

    /// The kept inventory of `router`.
    pub(crate) fn inventory(&self, router: &str) -> Option<Arc<TargetInventory>> {
        lock(&self.inventories).get(router).cloned()
    }

    /// The apply kcc runs or ran.
    pub(crate) fn live(&self) -> Option<Arc<Live>> {
        lock(&self.live).clone()
    }

    /// Keeps `live` as the apply.
    pub(crate) fn set_live(&self, live: Option<Arc<Live>>) {
        *lock(&self.live) = live;
    }

    /// Keeps the inventory of `router`.
    pub(crate) fn keep_inventory(&self, router: &str, inventory: Arc<TargetInventory>) {
        drop(lock(&self.inventories).insert(router.to_owned(), inventory));
    }
}

/// A lock whose holder cannot leave the data half-written, so a poisoned lock is used
/// as is.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
