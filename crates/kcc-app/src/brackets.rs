//! The safety brackets this process holds open.
//!
//! A bracket arms a router's recovery timer, does its work, disarms the timer and
//! reports. Once the arm is sent only the bracket's own end may stop it, so a server that
//! is shutting down waits for the open brackets before it exits. One [`Brackets`] exists
//! per process, owned by the change workflow; every bracket enters it through a
//! [`BracketGuard`], which leaves it when dropped, on every return path and on unwind.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use tokio::{sync::watch, time::timeout};

/// The process-wide count of open safety brackets.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Brackets {
    /// How many brackets are open.
    open: Arc<watch::Sender<usize>>,
}

impl Default for Brackets {
    #[inline]
    fn default() -> Self {
        Self {
            open: Arc::new(watch::Sender::new(0)),
        }
    }
}

impl Brackets {
    /// Counts one more open bracket until the returned guard is dropped.
    #[inline]
    #[must_use = "the bracket leaves the count when the guard is dropped"]
    pub fn enter(&self) -> BracketGuard {
        self.open
            .send_modify(|count| *count = count.saturating_add(1));
        BracketGuard {
            open: Arc::clone(&self.open),
        }
    }

    /// How many brackets are open now.
    #[inline]
    #[must_use]
    pub fn count(&self) -> usize {
        *self.open.borrow()
    }

    /// Waits until no bracket is open, at most `grace`; returns how many still are.
    // cancel-safe: only observes the count.
    #[inline]
    pub async fn drain(&self, grace: Duration) -> usize {
        let mut open = self.open.subscribe();
        drop(timeout(grace, open.wait_for(|count| *count == 0)).await);
        self.count()
    }
}

/// One open bracket in the process-wide count; dropping it leaves the count.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "the bracket leaves the count when the guard is dropped"]
pub struct BracketGuard {
    /// The count this bracket entered.
    open: Arc<watch::Sender<usize>>,
}

impl Drop for BracketGuard {
    #[inline]
    fn drop(&mut self) {
        self.open
            .send_modify(|count| *count = count.saturating_sub(1));
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions are not rendered API documentation"
)]
mod tests {
    use core::time::Duration;

    use tokio::time::Instant;

    use super::Brackets;

    /// The drain returns once the last guard is dropped and reports what is still open.
    #[tokio::test(start_paused = true)]
    async fn drain_waits_for_the_last_guard() {
        let brackets = Brackets::default();
        let first = brackets.enter();
        let second = brackets.enter();
        assert_eq!(brackets.count(), 2);
        drop(first);
        assert_eq!(brackets.drain(Duration::from_secs(1)).await, 1);
        let waiting = brackets.clone();
        let drained = tokio::spawn(async move { waiting.drain(Duration::from_secs(60)).await });
        drop(second);
        assert_eq!(drained.await.ok(), Some(0));
    }

    /// A bracket that stays open makes the drain wait its whole grace, then report it.
    #[tokio::test(start_paused = true)]
    async fn drain_reports_the_open_count_when_the_grace_elapses() {
        let brackets = Brackets::default();
        let _open = brackets.enter();
        let started = Instant::now();
        assert_eq!(brackets.drain(Duration::from_secs(10)).await, 1);
        assert_eq!(started.elapsed(), Duration::from_secs(10));
    }
}
