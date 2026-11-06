//! Management-interface safety execution.

use core::result::Result as CoreResult;

use kcc_app::workflow::{ChangeSet, CliChangeRequest, CliChangeResult, WorkflowError};
use kcc_catalog::Risk;

use crate::{
    DomainError, RouterCtx,
    configuration::{SafetyMode, SafetyNet, read_last_change},
};

/// Failures specific to guarded interface execution.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub struct InterfaceChangeError(InterfaceChangeErrorKind);

/// Internal guarded-execution failure categories.
#[derive(Debug, thiserror::Error)]
enum InterfaceChangeErrorKind {
    /// Explicit management confirmation was absent.
    #[error("management interface change requires explicit confirmation")]
    ConfirmationRequired,
    /// Domain planning or reachability failed.
    #[error(transparent)]
    Domain(#[from] DomainError),
    /// Protected workflow execution failed.
    #[error(transparent)]
    Workflow(#[from] WorkflowError),
}

impl InterfaceChangeError {
    /// Returns whether explicit management confirmation was absent.
    #[must_use]
    pub const fn is_confirmation_required(&self) -> bool {
        matches!(self.0, InterfaceChangeErrorKind::ConfirmationRequired)
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

/// Applies a change with fail-safe protection when management connectivity is at risk.
pub(super) async fn apply(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    request: CliChangeRequest,
    risk: Risk,
    confirmed: bool,
) -> CoreResult<CliChangeResult, InterfaceChangeError> {
    if risk == Risk::Management && !confirmed {
        return Err(InterfaceChangeError(
            InterfaceChangeErrorKind::ConfirmationRequired,
        ));
    }
    if risk != Risk::Management {
        return changes.apply_cli(request).await.map_err(Into::into);
    }
    drop(SafetyNet::arm(changes, router, SafetyMode::Router, 300).await?);
    let result = changes.apply_cli(request).await?;
    drop(read_last_change(router).await?);
    drop(SafetyNet::disarm(changes, router, SafetyMode::Router).await?);
    Ok(result)
}
