//! Cross-process ownership locks for running jobs.

extern crate alloc;

use alloc::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::JobError;
use crate::persist::{StateError, StateLock, StateStore};

/// Process-held advisory locks for active job identifiers.
pub(super) struct JobOwnership {
    /// State directory owning the lock sidecars.
    state: StateStore,
    /// Lock guards retained until each job reaches terminal cleanup.
    held: Mutex<BTreeMap<String, StateLock>>,
}

/// Releases a newly claimed job unless startup transfers it to the worker.
pub(super) struct JobOwnershipClaim<'ownership> {
    /// Ownership set containing the retained state lock.
    ownership: &'ownership JobOwnership,
    /// Claimed job identifier, cleared once transferred.
    id: Option<String>,
}

impl JobOwnership {
    /// Creates an empty ownership set rooted in `state`.
    pub(super) const fn new(state: StateStore) -> Self {
        Self {
            state,
            held: Mutex::new(BTreeMap::new()),
        }
    }

    /// Claims one job until the claim is transferred or dropped.
    pub(super) fn claim(&self, id: &str) -> Result<JobOwnershipClaim<'_>, JobError> {
        let lock = self.state.try_lock(&lock_name(id))?;
        drop(self.held().insert(id.to_owned(), lock));
        Ok(JobOwnershipClaim {
            ownership: self,
            id: Some(id.to_owned()),
        })
    }

    /// Releases the ownership lock of a terminal job.
    pub(super) fn release(&self, id: &str) {
        drop(self.held().remove(id));
    }

    /// Returns whether another live process currently owns this job.
    pub(super) fn is_held(&self, id: &str) -> Result<bool, JobError> {
        match self.state.try_lock(&lock_name(id)) {
            Ok(lock) => {
                drop(lock);
                Ok(false)
            }
            Err(StateError::StateLocked { path: _ }) => Ok(true),
            Err(error) => Err(error.into()),
        }
    }

    /// Locks the in-process ownership set and recovers after a prior panic.
    fn held(&self) -> MutexGuard<'_, BTreeMap<String, StateLock>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl JobOwnershipClaim<'_> {
    /// Transfers the retained lock to the running job.
    pub(super) fn transfer(mut self) {
        self.id = None;
    }
}

impl Drop for JobOwnershipClaim<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.ownership.release(&id);
        }
    }
}

/// Derives the validated state-lock name of one job.
fn lock_name(id: &str) -> String {
    format!("job-owner-{id}")
}
