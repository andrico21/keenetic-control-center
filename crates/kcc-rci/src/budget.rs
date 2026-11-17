//! Shared admission budget for all clients of one router.

use alloc::sync::Arc;

use tokio::sync::Semaphore;

/// Concurrent requests one router admits by default.
pub const DEFAULT_CONCURRENCY: usize = 2;

/// A cloneable budget of [`DEFAULT_CONCURRENCY`] requests owned by a router registry entry.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Budget {
    /// Admission shared across credentials and dedicated background sessions.
    semaphore: Arc<Semaphore>,
}

impl Default for Budget {
    #[inline]
    fn default() -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(DEFAULT_CONCURRENCY)),
        }
    }
}

impl Budget {
    /// Shares the private semaphore with the request engine.
    pub(crate) fn semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(&self.semaphore)
    }
}
