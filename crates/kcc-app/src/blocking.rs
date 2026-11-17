//! Running state-store work on Tokio's blocking pool.

use std::{io, path::Path};

use tokio::task::spawn_blocking;
use tracing::{Dispatch, Span, dispatcher};

use crate::persist::StateError;

/// Runs `work` (file I/O, `flock` waits, sealing) on the blocking pool, under the caller's
/// tracing subscriber and span, and returns its result.
///
/// Dropping the returned future does not stop `work`: it runs to its end, so a write it
/// started completes and a lock it took is released inside it.
///
/// # Errors
///
/// Returns the error of `work`, or a [`StateError::Io`] on `place` when the task panicked
/// or was cancelled with the runtime.
// cancel-safe: dropped, the work still finishes on the blocking pool; nothing is torn.
pub(crate) async fn run<T, E, F>(place: &Path, work: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: From<StateError> + Send + 'static,
{
    let (dispatch, span) = (dispatcher::get_default(Dispatch::clone), Span::current());
    let traced = move || dispatcher::with_default(&dispatch, || span.in_scope(work));
    spawn_blocking(traced).await.unwrap_or_else(|error| {
        Err(StateError::Io {
            path: place.to_owned(),
            source: io::Error::other(error),
        }
        .into())
    })
}
