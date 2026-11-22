//! The installer's log lines of this attempt: the baseline before `opkg disk`, the poll
//! after it, and what a line means.

use core::result::Result as CoreResult;

use kcc_app::jobs::JobContext;
use kcc_telemetry::logs::{
    parser::{ParsedLog, parse_records_now},
    types::LogRecord,
};
use serde_json::Value;
use tokio::time::{Instant, timeout};

use super::{
    INSTALL_LIMIT, INSTALLED_MARKER, POLL_INTERVAL, SetupFailure, SetupProgress, SetupStep,
    job::report,
};
use crate::{Result, RouterCtx, logging};

/// The newest log records one read returns.
const LOG_LINES: u32 = 500;

/// The component prefix of the installer's lines.
const INSTALLER: &str = "Opkg::Manager";

/// What this attempt's installer lines say so far.
enum Seen {
    /// The success line.
    Installed,
    /// A failure line.
    Failed(SetupFailure),
    /// Neither yet; the last installer step seen.
    Running(Option<u8>),
}

/// The highest record id in the router log now (0 for an empty log): only records above it
/// belong to the attempt that starts next.
///
/// A JSON reply must carry the `log` record list. A text reply (the router answers an empty
/// log with text) counts as an empty log only while it carries no installer line: older
/// installer lines in text cannot be told from this attempt's by record id.
///
/// # Errors
///
/// [`SetupFailure::BaselineUnusable`] for a reply without a usable record list, or
/// [`SetupFailure::Step`] in step `install` when the log read fails.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, it only reads the log.
pub(super) async fn baseline(router: &RouterCtx, name: &str) -> CoreResult<u64, SetupFailure> {
    let text = logging::read_log(router, LOG_LINES)
        .await
        .map_err(|error| SetupFailure::Step {
            step: SetupStep::Install,
            reason: error.to_string(),
        })?;
    let log = match serde_json::from_str::<Value>(&text) {
        Ok(response) => {
            parse_records_now(name, &response).map_err(|_error| SetupFailure::BaselineUnusable)?
        }
        Err(_not_json) if text.contains(INSTALLER) => return Err(SetupFailure::BaselineUnusable),
        Err(_not_json) => ParsedLog::default(),
    };
    Ok(log
        .entries
        .iter()
        .map(|(id, _record)| *id)
        .max()
        .unwrap_or_default())
}

/// Polls the log every [`POLL_INTERVAL`] until a record above `baseline` reports the
/// install's success or failure, for at most [`INSTALL_LIMIT`].
///
/// A failed read is retried at the next poll: the installer runs on regardless.
///
/// # Errors
///
/// The job failure text: an installer failure line, no success line in time
/// ([`SetupFailure::MarkerMissing`]), or the job's cancellation
/// ([`SetupFailure::InstallContinues`]: the installer runs on).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, it only reads the log.
pub(super) async fn installed(
    context: &JobContext,
    router: &RouterCtx,
    name: &str,
    baseline: u64,
) -> CoreResult<(), String> {
    let cancellation = context.cancellation();
    let deadline = Instant::now()
        .checked_add(INSTALL_LIMIT)
        .ok_or_else(|| SetupFailure::MarkerMissing.to_string())?;
    let mut reported = None;
    loop {
        if timeout(POLL_INTERVAL, cancellation.cancelled())
            .await
            .is_ok()
        {
            return Err(SetupFailure::InstallContinues.to_string());
        }
        match read(router, name).await {
            Ok(log) => match classify(&log, baseline) {
                Seen::Installed => return Ok(()),
                Seen::Failed(failure) => return Err(failure.to_string()),
                Seen::Running(step) => {
                    if step > reported {
                        reported = step;
                        let percent = step
                            .unwrap_or_default()
                            .saturating_mul(4)
                            .saturating_add(72);
                        report(
                            context,
                            percent,
                            &SetupProgress::at(SetupStep::Verify, step),
                        );
                    }
                }
            },
            Err(error) => {
                tracing::warn!(router = name, error = %error, "entware install log read failed");
            }
        }
        if Instant::now() >= deadline {
            return Err(SetupFailure::MarkerMissing.to_string());
        }
    }
}

/// Reads the newest log records; a reply that is not a JSON record list (the router answers
/// an empty log with text) has none.
///
/// # Errors
///
/// Returns an error when the log read fails ([`crate::DomainError`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, it only reads the log.
async fn read(router: &RouterCtx, name: &str) -> Result<ParsedLog> {
    let text = logging::read_log(router, LOG_LINES).await?;
    Ok(serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|response| parse_records_now(name, &response).ok())
        .unwrap_or_default())
}

/// What the installer lines above `baseline` say, in id order; the first verdict wins.
fn classify(log: &ParsedLog, baseline: u64) -> Seen {
    let mut step = None;
    for record in log
        .entries
        .iter()
        .filter(|(id, _record)| *id > baseline)
        .filter_map(|(_id, record)| record.as_ref())
        .filter(|record| from_installer(record))
    {
        let message = record.message.as_str();
        if message.contains(INSTALLED_MARKER) {
            return Seen::Installed;
        }
        if message.contains("doinstall") {
            if message.contains("Exec format error") {
                return Seen::Failed(SetupFailure::WrongArchitecture);
            }
            if message.contains("Error") || message.contains("error") {
                return Seen::Failed(SetupFailure::InstallerError {
                    installer_step: step.unwrap_or_default(),
                });
            }
        }
        step = installer_step(message).or(step);
    }
    Seen::Running(step)
}

/// Whether `record` is an installer line: its component is `Opkg::Manager`, or its text
/// still carries that prefix (behind another prefix the parser did not split).
fn from_installer(record: &LogRecord) -> bool {
    record.component.as_deref() == Some(INSTALLER)
        || record.message.contains(&format!("{INSTALLER}: "))
}

/// The installer step `N` of the first `[N/5]` in `message`.
fn installer_step(message: &str) -> Option<u8> {
    let (_before, after) = message.split_once('[')?;
    let (digit, _rest) = after.split_once("/5]")?;
    digit
        .parse::<u8>()
        .ok()
        .filter(|step| (1..=5).contains(step))
}
