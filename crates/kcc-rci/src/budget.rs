//! Shared admission budget for all clients of one router.

use alloc::sync::Arc;

use tokio::sync::Semaphore;

/// A cloneable two-request budget owned by a router registry entry.
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
            semaphore: Arc::new(Semaphore::new(2)),
        }
    }
}

impl Budget {
    /// Shares the private semaphore with the request engine.
    pub(crate) fn semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(&self.semaphore)
    }
}
