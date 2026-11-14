//! Shared retry timing for log sink workers.

use core::{fmt::Debug, pin::Pin, time::Duration};

use tokio::time::sleep;

/// Maximum delay between sink delivery attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Injectable asynchronous clock used by retry workers.
pub trait Clock: Debug + Send + Sync {
    /// Waits for `duration` without blocking the runtime.
    fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// Tokio-backed production clock.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct TokioClock;

impl Clock for TokioClock {
    #[inline]
    fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(sleep(duration))
    }
}

/// Computes capped exponential backoff with deterministic bounded jitter.
pub(super) fn delay(attempt: u32, retry_after: Option<Duration>) -> Duration {
    let exponent = attempt.min(5);
    let base = Duration::from_secs(1_u64 << exponent);
    let jitter = Duration::from_millis(u64::from(attempt.saturating_mul(137).min(250)));
    let backoff = base.saturating_add(jitter).min(MAX_BACKOFF);
    retry_after.map_or(backoff, |requested| requested.max(backoff).min(MAX_BACKOFF))
}
