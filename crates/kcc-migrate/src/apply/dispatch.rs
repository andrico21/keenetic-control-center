//! Protected submission with rejection-triggered NS3 compatibility.

use kcc_app::workflow::{ReplayOutcome, ReplayPolicy, ReplayResult};
use kcc_catalog::Catalog;
use secrecy::ExposeSecret as _;

use super::{Applier, ApplyError, command};
use crate::planner::PlannedLine;

/// Sends encoded input first unless plaintext compatibility was explicitly selected.
///
/// # Errors
/// Returns value-free validation and workflow failures.
// NOT cancel-safe: a transmitted command may apply before its receipt arrives.
pub(super) async fn submit(
    applier: &mut Applier,
    catalog: &Catalog,
    line: &PlannedLine,
) -> Result<ReplayResult, ApplyError> {
    let decoded = if applier.options.decode_ns3 {
        command::decoded(line.expose_command())?
    } else {
        None
    };
    let text = decoded
        .as_ref()
        .map_or_else(|| line.expose_command(), |secret| secret.expose_secret());
    let initial = command::build(catalog, text)?;
    let result = applier
        .changes
        .replay(&[initial], ReplayPolicy::StopOnError)
        .await
        .map_err(|_error| ApplyError::Workflow)?;
    if !applier.options.decode_ns3
        && result.outcomes == [ReplayOutcome::Rejected]
        && result.completion.is_ok()
        && let Some(plaintext) = command::decoded(line.expose_command())?
    {
        let retry = command::build(catalog, plaintext.expose_secret())?;
        return applier
            .changes
            .replay(&[retry], ReplayPolicy::StopOnError)
            .await
            .map_err(|_error| ApplyError::Workflow);
    }
    Ok(result)
}
