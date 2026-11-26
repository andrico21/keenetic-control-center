//! Which failed segment steps must be rolled back with the steps that succeeded.

use kcc_app::workflow::WorkflowError;
use kcc_rci::RciError;

/// Whether a failed step's own request may have changed the router.
///
/// A failure at or after dispatch (read-back, audit, an unknown transport outcome) may have
/// left the step applied, so its delete line runs with the earlier steps' rollback. Local
/// refusals and a refusal reported by the router changed nothing: running the delete line
/// could remove configuration that was there before the creation began.
pub(super) const fn may_have_changed_router(error: &WorkflowError) -> bool {
    matches!(
        error,
        WorkflowError::VerificationFailed { field: _ }
            | WorkflowError::UndecodableConfig
            | WorkflowError::UnexpectedBody
            | WorkflowError::Audit(_)
            | WorkflowError::Rci(
                RciError::Transport(_)
                    | RciError::Timeout
                    | RciError::Http { status: _ }
                    | RciError::Decode(_)
            )
    )
}
