//! Protected IPv6 route removal and wipe recovery.

use kcc_app::workflow::{ChangeSet, CliChangeResult, WorkflowError};

use super::{plan_remove_ipv6, reports_cleared, request, restore};
use crate::{DomainError, Result, RouterCtx, routing::model::Ipv6Route};

/// Removes one IPv6 route through the guarded workflow.
pub(super) async fn remove(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    route: &Ipv6Route,
) -> Result<CliChangeResult> {
    let saved = restore::saved_ipv6(router).await?;
    let removal = plan_remove_ipv6(router, route)?;
    let result = changes
        .apply_cli(request(&removal)?)
        .await
        .map_err(|error| {
            if matches!(error, WorkflowError::VerificationFailed { field: _ }) {
                DomainError::RouteCountMismatch
            } else {
                DomainError::Workflow(error)
            }
        })?;
    if reports_cleared(&result.responses) {
        return Err(restore::restore_ipv6(changes, router, saved).await);
    }
    Ok(result)
}
