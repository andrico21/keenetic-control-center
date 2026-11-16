//! Bounded acquisition of the cross-process audit append lock.

use core::time::Duration;
use std::process;

use tokio::time::sleep;

use crate::{
    audit::{AUDIT_FILE_NAME, AuditError},
    persist::{StateError, StateLock, StateStore},
};

/// Bounded retry policy for one append-lock acquisition.
#[derive(Clone, Copy, Debug)]
pub(super) struct RetryPolicy {
    /// Number of non-blocking attempts before an append fails.
    attempts: u16,
    /// First contention delay.
    initial_delay: Duration,
    /// Maximum backoff delay before per-process jitter.
    maximum_delay: Duration,
}

impl RetryPolicy {
    /// Production policy: rounds of roughly twenty-five seconds under continuous contention.
    pub(super) const PRODUCTION: Self = Self {
        attempts: 256,
        initial_delay: Duration::from_millis(10),
        maximum_delay: Duration::from_millis(100),
    };

    /// Constructs a deterministic policy for tests.
    #[cfg(test)]
    pub(super) const fn testing(
        attempts: u16,
        initial_delay: Duration,
        maximum_delay: Duration,
    ) -> Self {
        Self {
            attempts,
            initial_delay,
            maximum_delay,
        }
    }

    /// Exponential backoff with a small process-specific phase offset.
    fn delay(self, attempt: u16) -> Duration {
        let shift = u32::from(attempt.min(6));
        let multiplier = 1_u32.checked_shl(shift).unwrap_or(u32::MAX);
        let backoff = self.initial_delay.saturating_mul(multiplier);
        let capped = backoff.min(self.maximum_delay);
        let phase = process::id()
            .wrapping_add(u32::from(attempt))
            .wrapping_rem(11);
        capped.saturating_add(Duration::from_millis(u64::from(phase)))
    }
}

/// Acquires the audit lock without blocking a Tokio worker on the operating system lock.
///
/// # Errors
///
/// Returns [`AuditError::AppendLockTimeout`] after one bounded round of attempts, or the
/// underlying state error when opening or locking the sidecar fails.
// cancel-safe: every failed attempt owns no lock, and a successful lock is returned by value.
pub(super) async fn acquire_append_lock(
    store: &StateStore,
    policy: RetryPolicy,
) -> Result<StateLock, AuditError> {
    for attempt in 0..policy.attempts {
        match store.try_lock(AUDIT_FILE_NAME) {
            Ok(lock) => return Ok(lock),
            Err(StateError::StateLocked { path: _ })
                if attempt.saturating_add(1) < policy.attempts =>
            {
                sleep(policy.delay(attempt)).await;
            }
            Err(StateError::StateLocked { path: _ }) => return Err(AuditError::AppendLockTimeout),
            Err(error) => return Err(AuditError::State(error)),
        }
    }
    Err(AuditError::AppendLockTimeout)
}
