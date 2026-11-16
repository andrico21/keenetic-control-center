//! Every migration record of this process, each locked on its own, so one migration's
//! router work (a commit, a rollback that waits for a reboot) never holds another's.
//!
//! A record holds the target's write lease from its apply until a finish, or until the
//! router's recovery timer runs out: then the router has restored its startup
//! configuration on its own, and the lease is let go. A record without a lease is kept
//! for an hour (from its planning, or from its closing), and at most
//! [`PLANS`] unapplied plans are kept; older ones are forgotten when a plan is recorded.

use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};
use core::time::Duration;
use std::sync::{Mutex as StdMutex, MutexGuard as StdGuard, PoisonError};

use kcc_migrate::apply::Applier;
use tokio::{
    sync::{Mutex, MutexGuard},
    time::{Instant, sleep},
};

use super::state::Migration;
use crate::McpFailure;

/// How long a record without a lease is kept.
const KEPT_FOR: Duration = Duration::from_hours(1);

/// Unapplied plans kept at most; the oldest is forgotten first.
const PLANS: usize = 64;

/// Where a record is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Planned at this instant, not applied.
    Planned(Instant),
    /// An apply of the plan runs and has no lease yet.
    Applying,
    /// The apply's lease is held.
    Leased,
    /// The lease was let go at this instant.
    Closed(Instant),
}

/// One record and its own lock.
#[derive(Debug)]
pub(crate) struct Entry {
    /// The target router's id.
    target: String,
    /// Where the record is in its life, readable without its lock.
    phase: StdMutex<Phase>,
    /// The record.
    migration: Mutex<Migration>,
}

impl Entry {
    /// Wraps `migration`, watching its lease when it holds one.
    fn new(migration: Migration) -> Arc<Self> {
        let left = migration.recovery_left();
        let phase = if left.is_some() {
            Phase::Leased
        } else {
            Phase::Planned(Instant::now())
        };
        let entry = Arc::new(Self {
            target: migration.target().as_str().to_owned(),
            phase: StdMutex::new(phase),
            migration: Mutex::new(migration),
        });
        if let Some(left) = left {
            drop(tokio::spawn(expire(Arc::downgrade(&entry), left)));
        }
        entry
    }

    /// Locks the record, for reading or for its router work.
    // cancel-safe: only waits for the lock.
    pub(crate) async fn lock(&self) -> MutexGuard<'_, Migration> {
        self.migration.lock().await
    }

    /// Marks an apply of the record as running, so the record is not forgotten under it;
    /// dropping the mark without [`Entry::lease`] makes the record a plan again.
    ///
    /// # Errors
    ///
    /// Returns `conflict` while another apply of the record runs or after one.
    pub(crate) fn applying(self: &Arc<Self>) -> Result<Applying, McpFailure> {
        let mut phase = lock(&self.phase);
        let Phase::Planned(_) = *phase else {
            return Err(McpFailure::Conflict);
        };
        *phase = Phase::Applying;
        drop(phase);
        Ok(Applying(Arc::clone(self)))
    }

    /// Keeps the apply's `job` and `applier` in `migration` (this entry's, locked), and
    /// lets the lease go once the router's recovery window ends.
    pub(crate) fn lease(
        self: &Arc<Self>,
        migration: &mut Migration,
        job: String,
        applier: Applier,
    ) {
        let left = applier.recovery_left();
        migration.record_apply(job, applier);
        *lock(&self.phase) = Phase::Leased;
        drop(tokio::spawn(expire(Arc::downgrade(self), left)));
    }

    /// Lets go of the lease of `migration` (this entry's, locked), keeping its report.
    pub(crate) fn close(&self, migration: &mut Migration) {
        migration.close();
        *lock(&self.phase) = Phase::Closed(Instant::now());
    }

    /// Where the record is in its life.
    fn phase(&self) -> Phase {
        *lock(&self.phase)
    }
}

/// A running apply of a record; see [`Entry::applying`].
#[derive(Debug)]
pub(crate) struct Applying(Arc<Entry>);

impl Drop for Applying {
    fn drop(&mut self) {
        let mut phase = lock(&self.0.phase);
        if *phase == Phase::Applying {
            *phase = Phase::Planned(Instant::now());
        }
    }
}

/// Lets go of the lease of `entry` once `left` passed, unless a finish came first.
// cancel-safe: cancelled while waiting, the lease stays where it was; after the wait,
// only the record's own lock is awaited.
async fn expire(entry: Weak<Entry>, left: Duration) {
    sleep(left).await;
    let Some(entry) = entry.upgrade() else {
        return;
    };
    let mut migration = entry.lock().await;
    if migration.leased() {
        tracing::warn!(
            target = entry.target,
            "migration not finished in the recovery window; lease released"
        );
        entry.close(&mut migration);
    }
}

/// Every migration record of this process.
#[derive(Debug, Default)]
pub(crate) struct Migrations {
    /// Records by router-qualified plan id.
    entries: StdMutex<BTreeMap<String, Arc<Entry>>>,
}

impl Migrations {
    /// Records `migration` unless an apply on its target runs or still holds the lease;
    /// first forgets records past their time and the oldest plans past
    /// [`PLANS`].
    ///
    /// # Errors
    ///
    /// Returns `conflict` while an apply on the target runs or holds its lease.
    pub(crate) fn record(&self, migration: Migration) -> Result<Arc<Entry>, McpFailure> {
        let mut entries = lock(&self.entries);
        forget_old(&mut entries, Instant::now());
        let target = migration.target().as_str();
        if entries.values().any(|existing| {
            existing.target == target && matches!(existing.phase(), Phase::Applying | Phase::Leased)
        }) {
            return Err(McpFailure::Conflict);
        }
        let key = migration.key().to_owned();
        let entry = Entry::new(migration);
        drop(entries.insert(key, Arc::clone(&entry)));
        drop(entries);
        Ok(entry)
    }

    /// The record `id`.
    pub(crate) fn get(&self, id: &str) -> Option<Arc<Entry>> {
        lock(&self.entries).get(id).cloned()
    }
}

/// Forgets, at `now`, the records without a lease kept past [`KEPT_FOR`], and the
/// oldest unapplied plans until fewer than [`PLANS`] remain.
fn forget_old(entries: &mut BTreeMap<String, Arc<Entry>>, now: Instant) {
    entries.retain(|_, entry| match entry.phase() {
        Phase::Planned(at) | Phase::Closed(at) => now.saturating_duration_since(at) <= KEPT_FOR,
        Phase::Applying | Phase::Leased => true,
    });
    let mut planned = entries
        .iter()
        .filter_map(|(key, entry)| match entry.phase() {
            Phase::Planned(at) => Some((at, key.clone())),
            Phase::Applying | Phase::Leased | Phase::Closed(_) => None,
        })
        .collect::<Vec<_>>();
    planned.sort();
    let excess = planned.len().saturating_add(1).saturating_sub(PLANS);
    for (_, key) in planned.into_iter().take(excess) {
        drop(entries.remove(&key));
    }
}

/// A lock whose holder cannot leave the data half-written, so a poisoned lock is used
/// as is.
fn lock<T>(mutex: &StdMutex<T>) -> StdGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
