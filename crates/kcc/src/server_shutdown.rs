//! How `kcc serve` and `kcc mcp stdio` stop.
//!
//! A fatal audit-writer failure drains the requests in flight the way SIGTERM does. Then
//! requests on any surface (Web UI, MCP over HTTP or stdio) still closing a router's
//! safety bracket get a bounded grace before the process exits: every bracket enters the
//! change workflow's count ([`kcc_app::brackets::Brackets`]) whichever surface opened it.
//! Last, the audit writer gets a bounded time to write the entries still queued behind
//! another process's append lock; those still queued then are lost, and counted in the
//! log.

use core::time::Duration;

use kcc_app::{
    audit::{AuditLog, receipt::AUDIT_FLUSH_WAIT},
    brackets::Brackets,
};
use rmcp_server_kit::RmcpServerKitError;

use crate::server_error::ServerError;

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
        return result.map_err(ServerError::from);
    }
    tracing::error!("audit writer terminated; finishing the requests in flight before exit");
    stop();
    if let Err(source) = serving.await {
        tracing::warn!(%source, "listener stopped with an error after the audit writer terminated");
    }
    Err(ServerError::AuditWriterTerminated)
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

/// Gives the audit writer at most [`AUDIT_FLUSH_WAIT`] to write the entries still queued,
/// and logs how many are lost with the process.
// cancel-safe: only observes the writer's progress.
pub(crate) async fn flush_audit(audit: &AuditLog) {
    let queued = audit.flush(AUDIT_FLUSH_WAIT).await;
    if queued != 0 {
        tracing::error!(
            queued,
            "audit entries still queued at exit are lost; the append lock stayed busy or the writer failed"
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

    use kcc_app::{
        audit::{AUDIT_FILE_NAME, Actor, ActorKind, AuditEvent, AuditLog},
        brackets::Brackets,
        persist::StateStore,
    };
    use tempfile::TempDir;
    use tracing::subscriber::set_default;
    use tracing_subscriber::fmt::MakeWriter;

    use super::{flush_audit, wait_for_brackets};

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

    /// Entries still queued behind another process's append lock when the flush wait
    /// ends are logged as an error with their count.
    #[tokio::test(start_paused = true)]
    async fn entries_still_queued_at_exit_are_counted() -> Result<(), Box<dyn Error>> {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(captured.clone())
            .finish();
        let _default = set_default(subscriber);
        let temp = TempDir::new()?;
        let state = StateStore::open(&temp.path().join("state"))?;
        let audit = AuditLog::spawn(&state)?;
        let held = state.try_lock(AUDIT_FILE_NAME)?;
        for index in 0_u64..2 {
            let event = AuditEvent::new(
                index,
                Actor::new(ActorKind::System, "test".to_owned()),
                "test.flush".to_owned(),
            )
            .with_result("success".to_owned(), format!("flush-{index}"));
            drop(audit.submit(event)?);
        }

        flush_audit(&audit).await;
        drop(held);

        let output = String::from_utf8(
            captured
                .0
                .lock()
                .map_err(|_poisoned| "capture lock poisoned")?
                .clone(),
        )?;
        assert!(
            output.contains(" ERROR ") && output.contains("queued=2"),
            "{output}"
        );
        Ok(())
    }
}
