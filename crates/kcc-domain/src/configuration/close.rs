//! The closing step of a recovery bracket: keep the changes unsaved, save them, or roll back.

use alloc::vec;

use kcc_app::{
    permissions::Permission,
    workflow::{ChangeSet, CliChangeRequest, CliCommand as ValidatedCli, WorkflowError},
};
use kcc_catalog::HttpMethod;
use serde_json::json;

use super::{
    SafetyMode, SafetyNet,
    recovery::{self, Failure},
};
use crate::RouterCtx;

/// How a recovery bracket ends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Close {
    /// Disarms recovery and leaves the running configuration unsaved.
    KeepUnsaved,
    /// Persists the running configuration and resolves recovery.
    Save,
    /// Returns the router to its saved configuration.
    Rollback,
}

/// What a completed closing step did on the router.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Closed {
    /// The running configuration was persisted.
    pub saved: bool,
    /// The router is restarting to complete the step.
    pub restarting: bool,
}

/// Ends a recovery bracket armed with `mode` by `step`, sending the disarm or rollback
/// command under `permission`.
///
/// `permission` is the permission of the run the bracket protects for a keep, a save, or
/// the rollback of a failed run, and [`SafetyNet::CONTROL_PERMISSION`] for a rollback the
/// user chose. A save also needs [`Permission::Save`] for its commit and save.
///
/// `KeepUnsaved` disarms. `Save` commits the native fail-safe in router mode (the commit
/// saves the startup configuration and returns once `unsaved` cleared), or saves and then
/// cancels the scheduled reboot. `Rollback` sends the native fail-safe rollback in router
/// mode, or reboots at once so the router starts from its saved configuration.
///
/// # Errors
///
/// A failure that is still armed and not applied when the step's first command fails;
/// armed with [`ArmedFate::Saved`](super::bracket::ArmedFate::Saved) when the
/// configuration was saved but the scheduled reboot could not be cancelled; armed with
/// [`ArmedFate::Applied`](super::bracket::ArmedFate::Applied) and applied when
/// keep-unsaved could not disarm.
// NOT cancel-safe: cancelled after a command is sent, the router may have saved, disarmed,
// rolled back or started rebooting while the caller still treats recovery as armed.
#[inline]
pub async fn close(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    mode: SafetyMode,
    (step, permission): (Close, Permission),
) -> Result<Closed, Failure<WorkflowError>> {
    let saved = Closed {
        saved: true,
        restarting: false,
    };
    match (step, mode) {
        (Close::KeepUnsaved, _) => {
            let disarm = SafetyNet::disarm(changes, router, mode, permission).await;
            recovery::finish(
                Ok(Closed {
                    saved: false,
                    restarting: false,
                }),
                disarm,
            )
        }
        (Close::Save, SafetyMode::Router) => {
            changes.commit().await.map_err(Failure::armed)?;
            Ok(saved)
        }
        (Close::Save, SafetyMode::ScheduledReboot) => {
            changes.save().await.map_err(Failure::armed)?;
            SafetyNet::disarm(changes, router, mode, permission)
                .await
                .map(|_disarmed| saved)
                .map_err(Failure::saved)
        }
        (Close::Rollback, _) => {
            let path = match mode {
                SafetyMode::Router => "system configuration fail-safe rollback",
                SafetyMode::ScheduledReboot => "system reboot",
            };
            let validated = router
                .catalog
                .validate(path, HttpMethod::Post, &json!({}))
                .map_err(|issues| Failure::armed(WorkflowError::CatalogValidation { issues }))?;
            let request = CliChangeRequest::terminal(
                vec![
                    ValidatedCli::new(path.to_owned(), validated)
                        .map_err(|error| Failure::armed(WorkflowError::from(error)))?,
                ],
                permission,
                json!({"operation": path}),
            );
            drop(
                changes
                    .apply_recovery(request)
                    .await
                    .map_err(Failure::armed)?,
            );
            Ok(Closed {
                saved: false,
                restarting: mode == SafetyMode::ScheduledReboot,
            })
        }
    }
}
