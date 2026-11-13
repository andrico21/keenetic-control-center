//! What the CLI reports for the closing step of a recovery bracket.

use kcc_app::workflow::WorkflowError;
use kcc_domain::configuration::{
    close::{Close, Closed},
    recovery,
};
use kcc_i18n::keys;

use super::{
    exit::{Exit, Failure},
    output::Out,
};

/// Notes a persisted configuration and maps a failed closing step to its outcome.
///
/// # Errors
///
/// Returns the saved-but-armed, committed-but-not-saved, disarm-failed or still-armed
/// failure of `step`.
pub(crate) fn reported(
    out: Out,
    step: Close,
    result: Result<Closed, recovery::Failure<WorkflowError>>,
) -> Result<Closed, Failure> {
    let saved = match &result {
        Ok(closed) => closed.saved,
        Err(error) => step == Close::Save && error.applied() && error.is_armed(),
    };
    if saved {
        out.note(&out.tr(keys::CLI_SAVED, &[]));
    }
    result.map_err(|error| {
        let (applied, armed) = (error.applied(), error.is_armed());
        let source = Failure::from(error.into_source());
        match (step, applied, armed) {
            (Close::Save, true, true) => {
                Failure::headline_only(Exit::Router, keys::FINISH_SAVED_ARMED)
            }
            (Close::Save, true, false) => {
                Failure::headline_only(Exit::Router, keys::MIGRATE_COMMITTED_NOT_SAVED)
            }
            (_, true, true) => {
                Failure::headline_only(source.exit(), keys::MANAGEMENT_DISARM_FAILED)
            }
            (_, false, true) => {
                Failure::headline_only(source.exit(), keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED)
            }
            (_, _, false) => source,
        }
    })
}
