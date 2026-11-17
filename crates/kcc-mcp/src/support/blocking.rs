//! Running file and sealing work on Tokio's blocking pool.

use tokio::task::spawn_blocking;
use tracing::{Dispatch, Span, dispatcher};

use crate::McpFailure;

/// Runs `work` on the blocking pool, under the caller's tracing subscriber and span, and
/// returns what it returned; a task that panicked or was cancelled with the runtime is
/// logged and answers `internal`.
///
/// Dropping the returned future does not stop `work`: a write it started completes.
///
/// # Errors
///
/// Returns [`McpFailure::Internal`] when the task did not finish.
// cancel-safe: dropped, the work still finishes on the blocking pool; nothing is torn.
pub(crate) async fn run<T, W>(work: W) -> Result<T, McpFailure>
where
    W: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (dispatch, span) = (dispatcher::get_default(Dispatch::clone), Span::current());
    let traced = move || dispatcher::with_default(&dispatch, || span.in_scope(work));
    spawn_blocking(traced).await.map_err(|error| {
        tracing::error!(%error, "MCP blocking task failed");
        McpFailure::Internal
    })
}
