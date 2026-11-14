//! A change the domain could not plan, as the page's form answers it.

use kcc_domain::{DomainError, RouterCtx};

use super::super::outcome::Failure;

/// A change the domain refused to plan: the domain's error, the failure it was audited
/// as, and the domain context it was planned with, for a form whose answer reads the
/// router.
#[non_exhaustive]
pub(crate) struct Unplanned<'call> {
    /// Why the domain refused the change.
    error: &'call DomainError,
    /// The refusal in the user's words, as audited.
    failure: Failure,
    /// The domain context the change was planned with.
    domain: &'call RouterCtx,
}

impl<'call> Unplanned<'call> {
    /// The refusal `error`, audited as `failure`, planned with `domain`.
    pub(super) const fn new(
        error: &'call DomainError,
        failure: Failure,
        domain: &'call RouterCtx,
    ) -> Self {
        Self {
            error,
            failure,
            domain,
        }
    }

    /// Why the domain refused the change.
    pub(crate) const fn error(&self) -> &'call DomainError {
        self.error
    }

    /// The domain context the change was planned with.
    pub(crate) const fn domain(&self) -> &'call RouterCtx {
        self.domain
    }

    /// The refusal in the user's words.
    pub(crate) fn into_failure(self) -> Failure {
        self.failure
    }
}
