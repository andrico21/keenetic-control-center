//! Protected IPv6 route removal and wipe recovery.

use kcc_app::workflow::{ChangeSet, CliChangeResult, WorkflowError};

use super::{plan_remove_ipv6, reports_cleared, request, restore};
use crate::{DomainError, Result, RouterCtx, routing::model::Ipv6Route};

/// Removes one IPv6 route through the guarded workflow.
///
/// # Errors
///
/// Returns an error when reading the saved routes fails or does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]), when the catalog refuses a
/// planned request ([`DomainError::Validation`]), when the removal cannot be rendered or
/// given a read-back ([`DomainError::InvalidResponse`]), when the change workflow fails in
/// dispatch or audit, or a rendered line does not bind to its request
/// ([`DomainError::Workflow`]), or when the read-back still finds the route
/// ([`DomainError::RouteCountMismatch`]). When the router reports a broad clear, the first
/// failure of restoring the saved routes is returned, or [`DomainError::SafetyAbort`] when
/// it succeeded.
// NOT cancel-safe: the route removal may be applied, or the restore of the saved routes left half
// done, when the future is dropped.
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
