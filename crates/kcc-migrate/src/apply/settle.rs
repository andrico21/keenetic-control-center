//! Recovery outcome when preflight stops after the recovery timer was armed.

use kcc_app::{permissions::Permission, workflow::ChangeSet};
use kcc_domain::{
    RouterCtx,
    configuration::{SafetyMode, SafetyNet},
};
use serde_json::Value;

use super::ApplyError;

/// Where preflight stopped relative to the rebooting component commit.
#[derive(Debug)]
pub(super) enum Stop {
    /// The router has not rebooted, so the timer armed before this step is still pending.
    Armed(ApplyError),
    /// The component commit was sent and reboots the router onto its saved configuration.
    Rebooted(ApplyError),
}

impl Stop {
    /// Arms recovery for `seconds` under the run's `Migrate`; an arm whose result was lost
    /// is disarmed.
    ///
    /// # Errors
    /// [`ApplyError::Workflow`] when the disarm after a lost arm succeeded, otherwise
    /// [`ApplyError::ArmUnconfirmed`].
    // NOT cancel-safe: the arm or the disarm can reach the router before the caller receives
    // its result.
    pub(super) async fn arm(
        changes: &mut ChangeSet,
        ctx: &RouterCtx,
        mode: SafetyMode,
        seconds: u64,
    ) -> Result<(), ApplyError> {
        if SafetyNet::arm(changes, ctx, mode, seconds, Permission::Migrate)
            .await
            .is_err()
        {
            return Err(Self::unconfirmed_arm(changes, ctx, mode).await);
        }
        Ok(())
    }

    /// Disarms after an arm whose result was lost, since the arm may still have reached the
    /// router, and returns the error to report.
    // NOT cancel-safe: the disarm can reach the router before the caller receives its result.
    async fn unconfirmed_arm(
        changes: &mut ChangeSet,
        ctx: &RouterCtx,
        mode: SafetyMode,
    ) -> ApplyError {
        match SafetyNet::disarm(changes, ctx, mode, Permission::Migrate).await {
            Ok(_receipt) => ApplyError::Workflow,
            Err(_cleanup) => ApplyError::ArmUnconfirmed,
        }
    }

    /// Disarms a pending timer, or checks that the reboot cleared it, and returns the
    /// error to report.
    ///
    /// The original error is kept only when no timer is left; otherwise the result is
    /// [`ApplyError::FinishFailed`], which reports recovery as still armed.
    // NOT cancel-safe: the disarm can reach the router before the caller receives its result.
    pub(super) async fn settle(
        self,
        changes: &mut ChangeSet,
        ctx: &RouterCtx,
        mode: SafetyMode,
    ) -> ApplyError {
        match self {
            Self::Armed(error) => {
                match SafetyNet::disarm(changes, ctx, mode, Permission::Migrate).await {
                    Ok(_receipt) => error,
                    Err(_cleanup) => ApplyError::FinishFailed,
                }
            }
            Self::Rebooted(error) => match changes.current_last_change().await {
                Ok(state) if state.fail_safe.get("active") != Some(&Value::Bool(true)) => error,
                Ok(_) | Err(_) => ApplyError::FinishFailed,
            },
        }
    }
}
