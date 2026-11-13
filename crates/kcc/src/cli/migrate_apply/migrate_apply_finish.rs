//! One-shot migration finish selection and audit receipts.

use kcc_app::audit::Attempt;
use kcc_migrate::apply::{Applier, ApplyError};

use super::{FinishAction, apply_failure};
use crate::cli::{
    context::{Ctx, Services},
    exit::Outcome,
};

/// Finishes one apply and records every failed terminal outcome.
///
/// # Errors
/// Returns the localized terminal failure after appending its audit receipt.
// NOT cancel-safe: a terminal request or audit append may complete before cancellation.
pub(super) async fn finish(
    ctx: &Ctx,
    services: &Services,
    target: &str,
    applier: &mut Applier,
    finish: FinishAction,
    apply_failure_value: Option<ApplyError>,
) -> Outcome<(&'static str, bool)> {
    let result = match (finish, apply_failure_value) {
        (_, Some(_)) | (FinishAction::Rollback, None) => {
            applier.rollback().await.map(|()| ("rollback", false))
        }
        (FinishAction::Commit, None) => applier.commit().await.map(|()| ("commit", false)),
        (FinishAction::Keep, None) => return Ok(("keep", false)),
    };
    match result {
        Ok(action) => Ok(action),
        Err(ApplyError::RollbackRestarting) => {
            let failed = Attempt::Failed {
                error: "router",
                fail_safe_armed: false,
            };
            ctx.attempt(services, "cli.change", Some(target), failed)
                .await;
            Ok(("rollback", true))
        }
        Err(error) => {
            let failed = Attempt::Failed {
                error: "router",
                fail_safe_armed: error.recovery_armed(),
            };
            ctx.attempt(services, "cli.change", Some(target), failed)
                .await;
            Err(apply_failure(error))
        }
    }
}
