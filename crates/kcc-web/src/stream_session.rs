//! The session behind an event stream.
//!
//! A stream is authorized once, when it opens. [`StreamSession`] then checks its session
//! again before every event and at least every [`RECHECK`]: the session must still exist
//! (not logged out, ended after an account change, or expired) and its role must still
//! be, in its live definition, the role the stream opened with. A stream also ends when
//! its session reaches its absolute lifetime. The checks never refresh the session's
//! idle deadline, so an open stream alone does not keep a session alive.

use core::time::Duration;

use axum::response::sse::Event;
use futures_util::{Stream, StreamExt as _};
use kcc_app::permissions::Role;
use tokio::time::{Instant, timeout_at};

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    session::SessionId,
    sse::StreamPermit,
};

/// The longest a stream sends without checking its session again.
pub(crate) const RECHECK: Duration = Duration::from_secs(5);

/// One open stream of a signed-in session: its slot in the per-session limit and what
/// it checks the session against.
pub(crate) struct StreamSession {
    /// Services holding the session table and the live roles.
    state: WebState,
    /// The session the stream belongs to.
    id: SessionId,
    /// The role the stream was authorized with.
    role: Role,
    /// When the session's absolute lifetime ends.
    ends_at: Instant,
    /// When the session is checked next without an event.
    check_at: Instant,
    /// The stream's slot; dropping it frees the slot.
    _permit: StreamPermit,
}

impl StreamSession {
    /// Reserves a stream for the request of `current` as `user`, or `None` when the
    /// session already holds [`crate::sse::MAX_STREAMS_PER_SESSION`] streams.
    pub(crate) fn open(
        state: &WebState,
        current: &CurrentSession,
        user: &CurrentUser,
    ) -> Option<Self> {
        let permit = state.streams().try_acquire(&current.stream_key())?;
        let now = Instant::now();
        let left = state.sessions().lifetime_left(current.session());
        Some(Self {
            state: state.clone(),
            id: current.id().clone(),
            role: user.role().clone(),
            // A lifetime past the clock's range cannot be scheduled: end at once.
            ends_at: now.checked_add(left).unwrap_or(now),
            check_at: now.checked_add(RECHECK).unwrap_or(now),
            _permit: permit,
        })
    }

    /// The next event of `source` while the session still backs the stream; `None` once
    /// `source` ends or the session does not.
    // cancel-safe: `StreamExt::next` and the session check lose nothing when dropped; an
    // event already taken from `source` is only lost together with the whole stream.
    pub(crate) async fn next_event<S>(&mut self, source: &mut S) -> Option<Event>
    where
        S: Stream<Item = Event> + Unpin,
    {
        loop {
            let wake = self.check_at.min(self.ends_at);
            match timeout_at(wake, source.next()).await {
                Ok(event) => {
                    let sent = event?;
                    return self.backed().await.then_some(sent);
                }
                Err(_elapsed) => {
                    if !self.backed().await {
                        return None;
                    }
                }
            }
        }
    }

    /// Whether the session still backs the stream: within its absolute lifetime, still
    /// in the table, and holding the same live role. Schedules the next check.
    // cancel-safe: one read of the session table.
    async fn backed(&mut self) -> bool {
        let now = Instant::now();
        self.check_at = now.checked_add(RECHECK).unwrap_or(now);
        if now >= self.ends_at {
            return false;
        }
        let Some(session) = self.state.sessions().peek(&self.id).await else {
            return false;
        };
        session
            .role()
            .and_then(|role| self.state.role(&role.name))
            .is_some_and(|live| live == self.role)
    }
}
