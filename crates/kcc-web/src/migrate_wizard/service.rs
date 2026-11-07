//! The wizards' in-memory side.
//!
//! One request at a time per migration, and the analysis each migration works on (its
//! parsed source and the target's inventory), read from the routers once and kept while
//! the migration is open.
//!
//! Everything here can be rebuilt from the files (`store`) and the routers, so a restart
//! loses no choice: the next request reads the routers again.

use alloc::{collections::BTreeMap, sync::Arc};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kcc_migrate::inventory::TargetInventory;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use super::{analysis::Analysis, live::Live};

/// Migrations kept in memory; the oldest one is forgotten first.
const KEPT: usize = 64;

/// The in-memory side of every open migration of one Web UI.
#[derive(Default)]
pub(super) struct Wizards {
    /// Migration id and its session, oldest first.
    sessions: Mutex<Vec<(String, Arc<Session>)>>,
    /// Target router and the migration applying to it, until that one finishes.
    active: Mutex<BTreeMap<String, String>>,
}

impl Wizards {
    /// Reserves `target` for migration `id`; `false` when another migration holds it.
    pub(super) fn claim(&self, target: &str, id: &str) -> bool {
        lock(&self.active)
            .entry(target.to_owned())
            .or_insert_with(|| id.to_owned())
            == id
    }

    /// Frees `target` when migration `id` holds it.
    pub(super) fn release(&self, target: &str, id: &str) {
        let mut active = lock(&self.active);
        if active.get(target).is_some_and(|holder| holder == id) {
            drop(active.remove(target));
        }
    }

    /// The session of migration `id`, created on first use.
    pub(super) fn session(&self, id: &str) -> Arc<Session> {
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
pub(super) struct Session {
    /// Held by the request working on the migration, so two tabs never interleave.
    turn: Arc<AsyncMutex<()>>,
    /// The analysis of the current source and target, keyed by the target it read.
    analysis: Mutex<BTreeMap<String, Arc<Analysis>>>,
    /// A router source's own inventory, keyed by the router, for the maps.
    hardware: Mutex<BTreeMap<String, Arc<TargetInventory>>>,
    /// The apply, while kcc runs it and until it finishes.
    live: Mutex<Option<Arc<Live>>>,
}

impl Session {
    /// Waits for the migration's turn; requests on one migration run one at a time, and
    /// each reads the record only once it holds the turn.
    pub(super) async fn turn(&self) -> OwnedMutexGuard<()> {
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

    /// Forgets the kept analysis: the source or the target changed.
    pub(super) fn forget(&self) {
        lock(&self.analysis).clear();
        lock(&self.hardware).clear();
    }

    /// The kept inventory of the source router `router`.
    pub(super) fn hardware(&self, router: &str) -> Option<Arc<TargetInventory>> {
        lock(&self.hardware).get(router).cloned()
    }

    /// The apply kcc runs or ran.
    pub(super) fn live(&self) -> Option<Arc<Live>> {
        lock(&self.live).clone()
    }

    /// Keeps `live` as the apply.
    pub(super) fn set_live(&self, live: Option<Arc<Live>>) {
        *lock(&self.live) = live;
    }

    /// Keeps the inventory of the source router `router`.
    pub(super) fn keep_hardware(&self, router: &str, inventory: Arc<TargetInventory>) {
        drop(lock(&self.hardware).insert(router.to_owned(), inventory));
    }
}

/// A lock whose holder cannot leave the data half-written, so a poisoned lock is used
/// as is.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
