//! The log of one Entware service: the router's own log records of its process, read
//! over RCI and masked unless the principal may reveal secrets. No file is read over SSH.

use kcc_app::{permissions::Permission, registry};
use kcc_config::mask::redact_text;
use kcc_ssh::grammar::ServiceName;
use kcc_telemetry::logs::{parser::parse_records_now, types::LogRecord};
use serde_json::Value;

use super::ssh::{Caller, error::EntwareError};
use crate::{DomainError, RouterCtx, logging};

/// Router log lines read before filtering by the service's process.
pub const READ_LINES: u32 = 1000;

/// The newest `max_lines` log records of `service`'s process, oldest first.
///
/// The process is the init script name without `S` and the start-order digits
/// (`S51dropbear` -> `dropbear`); the records come from the router's last
/// [`READ_LINES`] log lines. Their messages pass through the shared masker unless the
/// caller's role holds `RevealSecrets` on the router. A log the router answers as text
/// holds no records.
///
/// # Errors
/// [`EntwareError::PermissionDenied`] without `Destructive` on the router, before any
/// request; the log read's failure or an unreadable JSON log ([`EntwareError::Domain`]).
// NOT cancel-safe: the log read may sign in first (see `logging::read_log`).
#[inline]
pub async fn service_log(
    router: &RouterCtx,
    caller: &Caller<'_>,
    service: ServiceName,
    max_lines: u32,
) -> Result<Vec<LogRecord>, EntwareError> {
    registry::authorize(caller.role, Permission::Destructive, caller.router)
        .map_err(|_denied| EntwareError::PermissionDenied)?;
    let text = logging::read_log(router, READ_LINES).await?;
    let Ok(response) = serde_json::from_str::<Value>(&text) else {
        return Ok(Vec::new());
    };
    let parsed = parse_records_now(caller.router, &response)
        .map_err(|_error| DomainError::InvalidResponse)?;
    let process = base_name(&service);
    let mut records: Vec<LogRecord> = parsed
        .entries
        .into_iter()
        .filter_map(|(_id, record)| record)
        .filter(|record| record.process.as_deref() == Some(process))
        .collect();
    let excess = records
        .len()
        .saturating_sub(usize::try_from(max_lines).unwrap_or(usize::MAX));
    drop(records.drain(..excess));
    if registry::authorize(caller.role, Permission::RevealSecrets, caller.router).is_err() {
        for record in &mut records {
            record.message = redact_text(&record.message);
        }
    }
    Ok(records)
}

/// The process of an init script: its name without `S` and the two start-order digits.
fn base_name(service: &ServiceName) -> &str {
    let name = service.as_str();
    name.get(3..).unwrap_or(name)
}
