//! The wizards' in-memory side.
//!
//! One request at a time per run, and what each run works on (a migration's parsed
//! source and its target's inventory, a router's inventory), read from the routers once
//! and kept while the run is open.
//!
//! Everything here can be rebuilt from the files (`store`) and the routers, so a restart
//! loses no choice: the next request reads the routers again.
//!
//! Each wizard keeps its own [`Wizards`]: the turns, the inventories and the live apply
//! work the same way for every wizard.

use alloc::{collections::BTreeMap, sync::Arc};
use std::sync::Mutex;

use kcc_migrate::inventory::TargetInventory;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use super::{flow::Flow, live::Live};
use crate::sync::lock;

/// Runs kept in memory; past it, the oldest idle one is forgotten first.
const KEPT: usize = 64;

/// The in-memory side of every open run of one wizard of one Web UI.
pub(crate) struct Wizards<F>
where
    F: Flow,
{
    /// Run id and its session, oldest first.
    sessions: Mutex<Vec<(String, Arc<Session<F>>)>>,
    /// Target router and the run applying to it, until that one finishes.
    active: Mutex<BTreeMap<String, String>>,
}

impl<F> Default for Wizards<F>
where
    F: Flow,
{
    fn default() -> Self {
        Self {
            sessions: Mutex::default(),
            active: Mutex::default(),
        }
    }
}

impl<F> Wizards<F>
where
    F: Flow,
{
    /// Whether a run other than `id` holds `target`.
    pub(crate) fn held_by_other(&self, target: &str, id: &str) -> bool {
        lock(&self.active)
            .get(target)
            .is_some_and(|holder| holder != id)
    }

    /// Reserves `target` for run `id`, unless another run holds it.
    pub(crate) fn claim(self: &Arc<Self>, target: &str, id: &str) -> Option<Claim<F>> {
        let claimed = *lock(&self.active)
            .entry(target.to_owned())
            .or_insert_with(|| id.to_owned())
            == *id;
        claimed.then(|| Claim {
            wizards: Arc::clone(self),
            target: target.to_owned(),
            id: id.to_owned(),
            armed: true,
        })
    }

    /// Frees `target` when run `id` holds it.
    pub(crate) fn release(&self, target: &str, id: &str) {
        let mut active = lock(&self.active);
        if active.get(target).is_some_and(|holder| holder == id) {
            drop(active.remove(target));
        }
    }

    /// The session of run `id`, created on first use; the caller has checked that the
    /// run exists and is the user's.
    ///
    /// Past [`KEPT`] runs, the oldest idle session is forgotten: one no request or apply
    /// uses (only this list holds it, its turn is free and it keeps no apply).
    pub(crate) fn session(&self, id: &str) -> Arc<Session<F>> {
        let mut sessions = lock(&self.sessions);
        if let Some((_, found)) = sessions.iter().find(|(known, _)| known == id) {
            return Arc::clone(found);
        }
        if sessions.len() >= KEPT
            && let Some(idle) = sessions.iter().position(|(_, session)| session.idle())
        {
            drop(sessions.remove(idle));
        }
        let session = Arc::new(Session::default());
        sessions.push((id.to_owned(), Arc::clone(&session)));
        session
    }
}

/// A target reserved for one run's apply until the apply's job owns it: dropped before
/// [`Claim::disarm`], it frees the target again.
pub(crate) struct Claim<F>
where
    F: Flow,
{
    /// The wizards holding the reservation.
    wizards: Arc<Wizards<F>>,
    /// The reserved target.
    target: String,
    /// The run holding it.
    id: String,
    /// Whether dropping the claim frees the target.
    armed: bool,
}

impl<F> Claim<F>
where
    F: Flow,
{
    /// Hands the reservation to the started apply, which frees it when it ends.
    pub(crate) fn disarm(mut self) {
        self.armed = false;
    }
}

impl<F> Drop for Claim<F>
where
    F: Flow,
{
    fn drop(&mut self) {
        if self.armed {
            self.wizards.release(&self.target, &self.id);
        }
    }
}

/// One run's in-memory side.
pub(crate) struct Session<F>
where
    F: Flow,
{
    /// Held by the request working on the run, so two tabs never interleave.
    turn: Arc<AsyncMutex<()>>,
    /// The analysis of the current source and target, keyed by the target it read.
    analysis: Mutex<BTreeMap<String, Arc<F::Analysis>>>,
    /// A router's inventory, keyed by the router: a router source's own, for the maps, or
    /// a preset run's target.
    inventories: Mutex<BTreeMap<String, Arc<TargetInventory>>>,
    /// The apply, while kcc runs it and until it finishes.
    live: Mutex<Option<Arc<Live>>>,
}

impl<F> Default for Session<F>
where
    F: Flow,
{
    fn default() -> Self {
        Self {
            turn: Arc::default(),
            analysis: Mutex::default(),
            inventories: Mutex::default(),
            live: Mutex::default(),
        }
    }
}

impl<F> Session<F>
where
    F: Flow,
{
    /// Waits for the run's turn; requests on one run are served one at a time, and
    /// each reads the record only once it holds the turn.
    pub(crate) async fn turn(&self) -> OwnedMutexGuard<()> {
        Arc::clone(&self.turn).lock_owned().await
    }

    /// The kept analysis of `target`.
    pub(crate) fn analysis(&self, target: &str) -> Option<Arc<F::Analysis>> {
        lock(&self.analysis).get(target).cloned()
    }

    /// Keeps `analysis` of `target`, replacing any other.
    pub(crate) fn keep(&self, target: &str, analysis: Arc<F::Analysis>) {
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

    /// Whether nothing uses the session: only the list holds it, no request holds its
    /// turn and it keeps no apply.
    fn idle(self: &Arc<Self>) -> bool {
        Arc::strong_count(self) == 1 && self.turn.try_lock().is_ok() && lock(&self.live).is_none()
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
