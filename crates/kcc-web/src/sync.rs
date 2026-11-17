//! Locking helpers shared by the Web UI's in-memory state.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Locks `mutex`; a holder that panics cannot leave the short-lived data it guards
/// half-written, so a poisoned lock is used as is.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
