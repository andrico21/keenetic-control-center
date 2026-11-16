//! The recovery timer's own steps, sent without a configuration change's preflight.
//!
//! A disarm or keep-alive changes no configuration: it stops or restarts the router's
//! recovery timer. Refusing it because someone else changed the router, or because the
//! automatic backup failed, is what lets the timer fire and discard every unsaved change.
//! A rollback does at once what the armed timer would do anyway, so refusing it protects
//! nothing. So this path keeps the change's authorization (permission and router scope,
//! under the change set's lease), the catalog-validated lines, the read-back and the
//! audit entry, and skips the conflict check and the backup. It accepts only the timer's
//! own requests, so that it is no general way around them.

use kcc_rci::RciError;

use super::{
    ChangeSet, CliChangeRequest, CliChangeResult, WorkflowError, authorize, map_permission,
    read_last_change,
};

/// Catalog paths of the recovery timer's steps: arm or disarm, keep-alive, rollback, and
/// the scheduled reboot (or, as its rollback, the immediate one).
const TIMER_PATHS: [&str; 4] = [
    "system configuration fail-safe timer",
    "system configuration fail-safe keep-alive",
    "system configuration fail-safe rollback",
    "system reboot",
];

/// How a sent CLI change refreshes the state that later writes of the set are checked
/// against.
#[derive(Clone, Copy, Debug)]
pub(super) enum Refresh {
    /// The router matched the expected state before sending: the state afterwards becomes
    /// the expected one, and a failed read is the change's error.
    Required,
    /// As `Required`, but a failed read keeps the old expected state instead of failing
    /// the step it follows.
    Optional,
    /// The router had changed before sending, or that is unknown: the expected state is
    /// kept, so that the change is still refused by the set's later writes.
    Keep,
}

/// Sends one recovery-timer step; see the module documentation.
///
/// # Errors
///
/// Returns a local refusal for any other request, or permission, request, verification,
/// or audit errors.
// NOT cancel-safe: cancellation after transmission may leave the step applied unaudited.
pub(super) async fn run(
    changes: &mut ChangeSet,
    request: CliChangeRequest,
) -> Result<CliChangeResult, WorkflowError> {
    let timer_only = request
        .commands
        .iter()
        .all(|command| TIMER_PATHS.contains(&command.validated().path.as_str()));
    if !timer_only {
        return Err(RciError::Validation.into());
    }
    for command in &request.commands {
        drop(command.expose_for_send()?);
    }
    authorize(&changes.role, request.permission, &changes.router).map_err(map_permission)?;
    let refresh = match read_last_change(&changes.client).await {
        Ok(current) if current.checksum == changes.expected.checksum => Refresh::Optional,
        Ok(_) | Err(_) => Refresh::Keep,
    };
    changes.send_cli(request, refresh).await
}
