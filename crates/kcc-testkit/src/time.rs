//! Time sources for session expiry.
//!
//! The fake router never reads the wall clock directly. It asks a [`Clock`] for the time
//! elapsed since an arbitrary origin, so tests can swap in a [`MockClock`] and move time
//! forward past the session TTL without sleeping.

use core::{
    fmt::Debug,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use std::time::Instant;

/// A monotonic time source.
pub trait Clock: Send + Sync + Debug {
    /// Time elapsed since this clock's origin.
    fn now(&self) -> Duration;
}

/// The real monotonic clock, counting from its construction.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct SystemClock {
    /// The instant this clock counts from.
    origin: Instant,
}

impl SystemClock {
    /// A clock whose origin is now.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    #[inline]
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// A clock that moves only when [`MockClock::advance`] is called.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct MockClock {
    /// Milliseconds since the origin.
    millis: AtomicU64,
}

impl MockClock {
    /// A clock standing at its origin.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            millis: AtomicU64::new(0),
        }
    }

    /// Moves the clock forward by `by`, saturating at `u64::MAX` milliseconds.
    #[inline]
    pub fn advance(&self, by: Duration) {
        let step = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        let _: u64 = self
            .millis
            .update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.saturating_add(step)
            });
    }
}

impl Clock for MockClock {
    #[inline]
    fn now(&self) -> Duration {
        Duration::from_millis(self.millis.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::time::Duration;

    use super::{Clock as _, MockClock};

    /// A mock clock reports exactly the time it was advanced by.
    #[test]
    fn mock_clock_advances() {
        let clock = MockClock::new();
        clock.advance(Duration::from_secs(301));
        assert_eq!(clock.now(), Duration::from_secs(301));
    }
}
