//! Management-interface safety execution.

use core::result::Result as CoreResult;

use kcc_app::workflow::{ChangeSet, CliChangeRequest, CliChangeResult, WorkflowError};
use kcc_catalog::Risk;

use crate::{
    DomainError, RouterCtx,
    configuration::{SafetyMode, SafetyNet, read_last_change, recovery},
};

/// Shared verification pointer for the native fail-safe state.
const FAIL_SAFE_ACTIVE_FIELD: &str = "/fail-safe/active";

/// Failures specific to guarded interface execution.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub struct InterfaceChangeError(InterfaceChangeErrorKind);

/// Internal guarded-execution failure categories.
#[derive(Debug, thiserror::Error)]
enum InterfaceChangeErrorKind {
    /// Recovery was armed and cleanup did not complete.
    #[error("management recovery timer remains armed")]
    Recovery {
        /// Whether the protected work completed before cleanup failed.
        applied: bool,
    },
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
    /// Returns whether work completed when recovery remains armed.
    #[must_use]
    pub const fn armed_outcome(&self) -> Option<bool> {
        match self.0 {
            InterfaceChangeErrorKind::Recovery { applied } => Some(applied),
            InterfaceChangeErrorKind::ConfirmationRequired
            | InterfaceChangeErrorKind::Domain(_)
            | InterfaceChangeErrorKind::Workflow(_) => None,
        }
    }
    /// Returns whether explicit management confirmation was absent.
    #[must_use]
    pub const fn is_confirmation_required(&self) -> bool {
        matches!(self.0, InterfaceChangeErrorKind::ConfirmationRequired)
    }

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

/// Applies a change with fail-safe protection when management connectivity is at risk.
// NOT cancel-safe: cancellation after arming can leave work applied and recovery armed.
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
    let result = changes
        .apply_cli(request)
        .await
        .map_err(InterfaceChangeError::from);
    let verified = match result {
        Ok(applied) => read_last_change(router)
            .await
            .map(|_state| applied)
            .map_err(InterfaceChangeError::from),
        Err(error) => Err(error),
    };
    // Preserve the guard's early-return protocol: failed work never sends cleanup.
    let applied = verified.map_err(|_error| {
        InterfaceChangeError(InterfaceChangeErrorKind::Recovery { applied: false })
    })?;
    let disarm = SafetyNet::disarm(changes, router, SafetyMode::Router)
        .await
        .map_err(InterfaceChangeError::from);
    recovery::finish(Ok(applied), disarm).map_err(|error| {
        InterfaceChangeError(InterfaceChangeErrorKind::Recovery {
            applied: error.applied(),
        })
    })
}
