//! Reviewed source and target fingerprint checks.

use kcc_rci::SecretBytes;
use secrecy::ExposeSecret as _;

use super::{ApplyError, ApplyRequest, verify};
use crate::source::SourceConfig;

/// Compares canonical source and target identities captured by the planner.
///
/// # Errors
/// Returns drift or configuration decoding failures.
pub(super) fn check(
    request: &ApplyRequest,
    source: &SourceConfig,
    backup: &SecretBytes,
    running: &SecretBytes,
) -> Result<(), ApplyError> {
    let startup = SourceConfig::from_bytes(backup.expose_secret())
        .map_err(|_error| ApplyError::Validation)?;
    let active = SourceConfig::from_bytes(running.expose_secret())
        .map_err(|_error| ApplyError::Validation)?;
    let source_md5 = source
        .header
        .md5
        .clone()
        .unwrap_or_else(|| verify::normalized_digest(&source.ast));
    let source_marker = verify::digest(source.header.last_change.as_deref().unwrap_or_default());
    if source_md5 != request.plan.source_fingerprint.startup_md5
        || verify::normalized_digest(&active.ast) != request.plan.target_running_digest
        || source_marker != request.plan.source_fingerprint.last_change_checksum
        || startup.header.md5.as_deref()
            != Some(request.plan.target_fingerprint.startup_md5.as_str())
    {
        return Err(ApplyError::Drift);
    }
    Ok(())
}
