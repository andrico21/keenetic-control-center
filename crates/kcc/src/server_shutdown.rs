//! How `kcc serve` stops.
//!
//! A fatal audit-writer failure drains the requests in flight the way SIGTERM does, and
//! Web requests still closing a router's fail-safe bracket get a bounded grace before
//! the process exits.

use core::time::Duration;

use kcc_app::audit::AuditLog;
use kcc_web::brackets::Brackets;
use rmcp_server_kit::RmcpServerKitError;

use crate::server::{ServerError, error};

/// How long `kcc serve` waits, once its listener stopped, for Web requests still closing
/// a router's fail-safe bracket.
pub(crate) const BRACKET_GRACE: Duration = Duration::from_secs(10);

/// Serves until the kit stops (SIGTERM, Ctrl-C) or the audit writer dies.
///
/// A dead writer calls `stop`, the kit's graceful shutdown: no new connection is accepted and the
/// requests in flight finish and are answered, within `server.shutdown_timeout`, before
/// the writer's failure is returned.
///
/// # Errors
///
/// The kit's error, or the terminated audit writer.
// NOT cancel-safe: dropped, `serving` detaches the kit's shutdown tasks.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "tokio::select macro expansion contains runtime-internal remainder arithmetic"
)]
pub(crate) async fn serve_until_shutdown<F, S>(
    serving: F,
    audit: &AuditLog,
    stop: S,
) -> Result<(), ServerError>
where
    F: Future<Output = Result<(), RmcpServerKitError>>,
    S: FnOnce(),
{
    tokio::pin!(serving);
    let served = tokio::select! {
        result = &mut serving => Some(result),
        () = audit.closed() => None,
    };
    if let Some(result) = served {
        return result.map_err(error);
    }
    tracing::error!("audit writer terminated; finishing the requests in flight before exit");
    stop();
    if let Err(source) = serving.await {
        tracing::warn!(%source, "listener stopped with an error after the audit writer terminated");
    }
    Err(error("audit writer terminated"))
}

/// Waits, at most [`BRACKET_GRACE`], for Web requests still closing a router's fail-safe
/// bracket; their tasks run on although their connections are gone.
// cancel-safe: only observes the bracket count.
pub(crate) async fn wait_for_brackets(web: Option<&Brackets>) {
    let Some(brackets) = web else {
        return;
    };
    let open = brackets.drain(BRACKET_GRACE).await;
    if open != 0 {
        tracing::warn!(
            open,
            "Web requests still closing a router fail-safe bracket at exit; the router's timer remains armed for rollback"
        );
    }
}
