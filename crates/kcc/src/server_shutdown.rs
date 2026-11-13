//! How `kcc serve` and `kcc mcp stdio` stop.
//!
//! A fatal audit-writer failure drains the requests in flight the way SIGTERM does. Then
//! requests on any surface (Web UI, MCP over HTTP or stdio) still closing a router's
//! safety bracket get a bounded grace before the process exits: every bracket enters the
//! change workflow's count ([`kcc_app::brackets::Brackets`]) whichever surface opened it.

use core::time::Duration;

use kcc_app::{audit::AuditLog, brackets::Brackets};
use rmcp_server_kit::RmcpServerKitError;

use crate::server::{ServerError, error};

/// How long the server waits, once its transport stopped, for requests still closing a
/// router's safety bracket.
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

/// Waits, at most [`BRACKET_GRACE`], for requests on any surface still closing a router's
/// safety bracket; their tasks run on although their connections are gone.
// cancel-safe: only observes the bracket count.
pub(crate) async fn wait_for_brackets(brackets: &Brackets) {
    let open = brackets.drain(BRACKET_GRACE).await;
    if open != 0 {
        tracing::warn!(
            open,
            "requests still closing a router fail-safe bracket at exit; the router's timer remains armed for rollback"
        );
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions are not rendered API documentation"
)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::error::Error;
    use std::{io, sync::Mutex};

    use kcc_app::brackets::Brackets;
    use tracing::subscriber::set_default;
    use tracing_subscriber::fmt::MakeWriter;

    use super::wait_for_brackets;

    /// Everything the subscriber writes.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .map_err(|_poisoned| io::Error::other("capture lock poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl MakeWriter<'_> for Captured {
        type Writer = Self;

        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// A bracket still open when the grace ends is logged as a warning with the open count.
    #[tokio::test(start_paused = true)]
    async fn a_bracket_open_at_exit_is_warned_about() -> Result<(), Box<dyn Error>> {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(captured.clone())
            .finish();
        let _default = set_default(subscriber);
        let brackets = Brackets::default();
        let _open = brackets.enter();

        wait_for_brackets(&brackets).await;

        let output = String::from_utf8(
            captured
                .0
                .lock()
                .map_err(|_poisoned| "capture lock poisoned")?
                .clone(),
        )?;
        assert!(
            output.contains(" WARN ") && output.contains("open=1"),
            "{output}"
        );
        Ok(())
    }
}
