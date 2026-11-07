//! Cross-process ownership locks for running jobs.

extern crate alloc;

use alloc::collections::BTreeMap;

use tokio::sync::Mutex;

use super::JobError;
use crate::persist::{StateError, StateLock, StateStore};

/// Process-held advisory locks for active job identifiers.
pub(super) struct JobOwnership {
    /// State directory owning the lock sidecars.
    state: StateStore,
    /// Lock guards retained until each job reaches terminal cleanup.
    held: Mutex<BTreeMap<String, StateLock>>,
}

impl JobOwnership {
    /// Creates an empty ownership set rooted in `state`.
    pub(super) fn new(state: StateStore) -> Self {
        Self {
            state,
            held: Mutex::new(BTreeMap::new()),
        }
    }

    /// Claims one job until [`Self::release`] is called or the process exits.
    pub(super) async fn claim(&self, id: &str) -> Result<(), JobError> {
        let lock = self.state.try_lock(&lock_name(id))?;
        drop(self.held.lock().await.insert(id.to_owned(), lock));
        Ok(())
    }

    /// Releases the ownership lock of a terminal job.
    pub(super) async fn release(&self, id: &str) {
        drop(self.held.lock().await.remove(id));
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
}

/// Derives the validated state-lock name of one job.
fn lock_name(id: &str) -> String {
    format!("job-owner-{id}")
}
