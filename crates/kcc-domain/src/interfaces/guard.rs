//! Interface change execution: the change and, for a management change, its read-back.
//!
//! The recovery bracket around a management change belongs to the surface that runs it
//! (`configuration::bracket::guarded`), as for every other management change.

use core::result::Result as CoreResult;

use kcc_app::workflow::{ChangeSet, CliChangeRequest, CliChangeResult, WorkflowError};
use kcc_catalog::Risk;

use crate::{DomainError, RouterCtx, configuration::read_last_change};

/// Shared verification pointer for the native fail-safe state.
const FAIL_SAFE_ACTIVE_FIELD: &str = "/fail-safe/active";

/// Failures of an interface change.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub struct InterfaceChangeError(InterfaceChangeErrorKind);

/// Internal interface change failure categories.
#[derive(Debug, thiserror::Error)]
enum InterfaceChangeErrorKind {
    /// Domain planning or the read-back failed.
    #[error(transparent)]
    Domain(#[from] DomainError),
    /// Workflow execution failed.
    #[error(transparent)]
    Workflow(#[from] WorkflowError),
}

impl InterfaceChangeError {
    /// Returns whether the change was refused because the fail-safe timer did not arm.
    #[must_use]
    pub fn is_fail_safe_unarmed(&self) -> bool {
        matches!(
            &self.0,
            InterfaceChangeErrorKind::Workflow(WorkflowError::VerificationFailed { field })
                if field == FAIL_SAFE_ACTIVE_FIELD
        )
    }
}

impl From<DomainError> for InterfaceChangeError {
    fn from(error: DomainError) -> Self {
        Self(InterfaceChangeErrorKind::Domain(error))
    }
}

impl From<WorkflowError> for InterfaceChangeError {
    fn from(error: WorkflowError) -> Self {
        Self(InterfaceChangeErrorKind::Workflow(error))
    }
}

/// Applies `request`; a management change then reads `show last-change` back to prove the
/// router still answers.
// NOT cancel-safe: cancelled after the request is sent, the change may be applied without
// its read-back.
pub(super) async fn apply(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    request: CliChangeRequest,
    risk: Risk,
) -> CoreResult<CliChangeResult, InterfaceChangeError> {
    let applied = changes.apply_cli(request).await?;
    if risk == Risk::Management {
        drop(read_last_change(router).await?);
    }
    Ok(applied)
}
