//! Running file and sealing work on Tokio's blocking pool.

use std::io;

use tokio::task::spawn_blocking;
use tracing::{Dispatch, Span, dispatcher};

/// Runs `work` on the blocking pool, under the caller's tracing subscriber and span, and
/// returns its result; a task that panicked or was cancelled with the runtime becomes
/// `failed` of an I/O error, logged.
///
/// Dropping the returned future does not stop `work`: a write it started completes.
///
/// # Errors
///
/// Returns the error of `work`, or `failed` when the task did not finish.
// cancel-safe: dropped, the work still finishes on the blocking pool; nothing is torn.
pub(crate) async fn run<T, E, W>(work: W, failed: fn(io::Error) -> E) -> Result<T, E>
where
    W: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    let (dispatch, span) = (dispatcher::get_default(Dispatch::clone), Span::current());
    let traced = move || dispatcher::with_default(&dispatch, || span.in_scope(work));
    spawn_blocking(traced).await.unwrap_or_else(|error| {
        tracing::error!(%error, "blocking task failed");
        Err(failed(io::Error::other(error)))
    })
}
