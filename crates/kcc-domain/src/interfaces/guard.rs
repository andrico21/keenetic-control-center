//! Interface change execution and its error.
//!
//! The recovery bracket around a management change belongs to the surface that runs it
//! (`configuration::bracket::guarded`), as for every other management change.

use core::result::Result as CoreResult;

use kcc_app::workflow::{ChangeSet, CliChangeRequest, CliChangeResult, WorkflowError};

use crate::DomainError;

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

impl From<DomainError> for InterfaceChangeError {
    #[inline]
    fn from(error: DomainError) -> Self {
        Self(InterfaceChangeErrorKind::Domain(error))
    }
}

impl From<InterfaceChangeError> for DomainError {
    /// The domain failure an interface change failed with, for the front ends' one mapping.
    #[inline]
    fn from(error: InterfaceChangeError) -> Self {
        match error.0 {
            InterfaceChangeErrorKind::Domain(domain) => domain,
            InterfaceChangeErrorKind::Workflow(workflow) => Self::Workflow(workflow),
        }
    }
}

impl From<WorkflowError> for InterfaceChangeError {
    #[inline]
    fn from(error: WorkflowError) -> Self {
        Self(InterfaceChangeErrorKind::Workflow(error))
    }
}

/// Applies `request` through the change workflow, which reads the change back.
///
/// # Errors
///
/// Returns an error when the change workflow fails: dispatch, read-back or audit (a
/// [`WorkflowError`]).
// NOT cancel-safe: cancelled after the request is sent, the change may be applied without
// its read-back.
pub(super) async fn apply(
    changes: &mut ChangeSet,
    request: CliChangeRequest,
) -> CoreResult<CliChangeResult, InterfaceChangeError> {
    Ok(changes.apply_cli(request).await?)
}
