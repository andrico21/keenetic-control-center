//! Server-side accounting of overlapping request handlers.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Per-instance current and peak request counts.
#[derive(Debug, Default)]
pub(crate) struct Counter {
    /// Currently active handlers.
    active: AtomicUsize,
    /// Greatest observed overlap since construction.
    maximum: AtomicUsize,
}

impl Counter {
    /// Counts a request until its handler exits or is cancelled.
    pub(crate) fn enter(&self) -> Guard<'_> {
        let active = self.active.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        let _previous = self.maximum.fetch_max(active, Ordering::SeqCst);
        Guard(self)
    }

    /// Returns the largest observed handler overlap.
    pub(crate) fn maximum(&self) -> usize {
        self.maximum.load(Ordering::SeqCst)
    }
}

/// Releases accounting even when middleware is cancelled.
pub(crate) struct Guard<'counter>(&'counter Counter);

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        let _previous = self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}
