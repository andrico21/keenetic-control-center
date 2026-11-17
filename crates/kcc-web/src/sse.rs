//! The per-session cap on concurrent server-sent event streams.
//!
//! Stream routes run without the request timeout, so each one holds a [`StreamPermit`]
//! for as long as it streams; a session that already has
//! [`MAX_STREAMS_PER_SESSION`] open streams is refused another.

use alloc::{collections::BTreeMap, sync::Arc};
use core::fmt;
use std::sync::Mutex;

use crate::sync::lock;

/// Concurrent event streams one session may hold.
pub const MAX_STREAMS_PER_SESSION: usize = 4;

/// Counts the open event streams of every session.
///
/// Sessions are keyed by an opaque handle the session layer chooses, never by the
/// session cookie value; the [`fmt::Debug`] output shows only how many sessions hold
/// streams.
#[derive(Clone, Default)]
pub struct StreamLimiter {
    /// Open streams per session handle; a session with none has no entry.
    open: Arc<Mutex<BTreeMap<String, usize>>>,
}

impl fmt::Debug for StreamLimiter {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamLimiter")
            .field("sessions", &lock(&self.open).len())
            .finish()
    }
}

impl StreamLimiter {
    /// Reserves a stream for `session`, or `None` when it already holds
    /// [`MAX_STREAMS_PER_SESSION`] streams. Dropping the permit releases the stream.
    #[inline]
    #[must_use]
    pub fn try_acquire(&self, session: &str) -> Option<StreamPermit> {
        let mut open = lock(&self.open);
        let count = open.entry(session.to_owned()).or_default();
        if *count >= MAX_STREAMS_PER_SESSION {
            return None;
        }
        *count = count.saturating_add(1);
        drop(open);
        Some(StreamPermit {
            limiter: self.clone(),
            session: session.to_owned(),
        })
    }

    /// The streams `session` holds now.
    #[inline]
    #[must_use]
    pub fn open_streams(&self, session: &str) -> usize {
        lock(&self.open).get(session).copied().unwrap_or(0)
    }

    /// Releases one stream of `session`.
    fn release(&self, session: &str) {
        let mut open = lock(&self.open);
        if let Some(count) = open.get_mut(session) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                let _released: Option<usize> = open.remove(session);
            }
        }
    }
}

/// One reserved event stream; dropping it releases the stream.
#[must_use = "dropping the permit releases the stream immediately"]
pub struct StreamPermit {
    /// The limiter that issued the permit.
    limiter: StreamLimiter,
    /// The session holding the stream.
    session: String,
}

impl fmt::Debug for StreamPermit {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamPermit").finish_non_exhaustive()
    }
}

impl Drop for StreamPermit {
    #[inline]
    fn drop(&mut self) {
        self.limiter.release(&self.session);
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{MAX_STREAMS_PER_SESSION, StreamLimiter};

    #[test]
    fn a_session_holds_at_most_four_streams() {
        let limiter = StreamLimiter::default();
        let mut permits = Vec::new();
        for _ in 0..MAX_STREAMS_PER_SESSION {
            permits.push(limiter.try_acquire("alpha"));
        }
        assert!(permits.iter().all(Option::is_some), "four streams granted");
        assert!(limiter.try_acquire("alpha").is_none(), "fifth refused");
        assert!(
            limiter.try_acquire("beta").is_some(),
            "other sessions are independent"
        );
        drop(permits);
        assert_eq!(limiter.open_streams("alpha"), 0, "released on drop");
        let again = limiter.try_acquire("alpha");
        assert!(again.is_some(), "a released stream can be reopened");
        assert_eq!(limiter.open_streams("alpha"), 1, "one open");
    }

    #[test]
    fn clones_share_the_counters() {
        let limiter = StreamLimiter::default();
        let clone = limiter.clone();
        let permit = clone.try_acquire("gamma");
        assert!(permit.is_some(), "granted");
        assert_eq!(
            limiter.open_streams("gamma"),
            1,
            "visible through the original"
        );
        drop(permit);
        assert_eq!(limiter.open_streams("gamma"), 0, "released");
    }
}
