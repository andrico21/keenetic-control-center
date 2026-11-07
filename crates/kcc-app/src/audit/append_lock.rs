//! Bounded acquisition of the cross-process audit append lock.

use core::time::Duration;

use tokio::time::sleep;

use crate::{
    audit::{AUDIT_FILE_NAME, AuditError},
    persist::{StateError, StateLock, StateStore},
};

/// Number of non-blocking lock attempts before an append fails.
pub(super) const ATTEMPTS: u16 = 200;
/// Delay between non-blocking attempts.
pub(super) const RETRY_DELAY: Duration = Duration::from_millis(10);

/// Acquires the audit lock without blocking a Tokio worker on the operating system lock.
///
/// # Errors
///
/// Returns [`AuditError::AppendLockTimeout`] after the bounded retry window, or the
/// underlying state error when opening or locking the sidecar fails.
// cancel-safe: every failed attempt owns no lock, and a successful lock is returned by value.
pub(super) async fn acquire_append_lock(store: &StateStore) -> Result<StateLock, AuditError> {
    for attempt in 0..ATTEMPTS {
        match store.try_lock(AUDIT_FILE_NAME) {
            Ok(lock) => return Ok(lock),
            Err(StateError::StateLocked { path: _ }) if attempt.saturating_add(1) < ATTEMPTS => {
                sleep(RETRY_DELAY).await;
            }
            Err(StateError::StateLocked { path: _ }) => return Err(AuditError::AppendLockTimeout),
            Err(error) => return Err(AuditError::State(error)),
        }
    }
    Err(AuditError::AppendLockTimeout)
}
