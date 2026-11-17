//! Cross-process ownership locks for running jobs.

extern crate alloc;

use alloc::collections::BTreeMap;
use std::{
    fs, io,
    sync::{Mutex, MutexGuard, PoisonError},
};

use super::JobError;
use crate::persist::{StateError, StateLock, StateStore, io_error};

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
    ///
    /// # Errors
    /// [`JobError::IdCollision`] when another holder has the lock; otherwise the lock
    /// failure.
    pub(super) fn claim(&self, id: &str) -> Result<JobOwnershipClaim<'_>, JobError> {
        let lock = match self.state.try_lock(&lock_name(id)) {
            Ok(lock) => lock,
            Err(StateError::StateLocked { path: _ }) => return Err(JobError::IdCollision),
            Err(error) => return Err(error.into()),
        };
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
    ///
    /// # Errors
    /// The lock failure, other than the lock being held.
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

    /// Removes the lock file of a pruned job unless a live process still owns it.
    ///
    /// # Errors
    /// The lock failure, other than the lock being held, or the lock file removal failure.
    pub(super) fn discard(&self, id: &str) -> Result<(), JobError> {
        match self.state.try_lock(&lock_name(id)) {
            Ok(lock) => {
                let path = lock.path().to_path_buf();
                match fs::remove_file(&path) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(io_error(&path, error).into()),
                }
            }
            Err(StateError::StateLocked { path: _ }) => Ok(()),
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
