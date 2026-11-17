//! Why submitted values read against the router lead to no change.

use super::{super::outcome::Failure, Invalid};

/// Why a submission checked against what the router has stops before its change is
/// planned.
pub(crate) enum Rejected {
    /// Values that failed their check: answered by the form, audited `validation_failed`.
    Invalid(Invalid),
    /// The domain could not plan the change: answered where the form shows such a
    /// refusal, as a refusal of the planning step, audited with its reason.
    Refused(Failure),
    /// What the router has rules the change out, such as an object it no longer has or a
    /// router that could not be read: answered in the outcome region as a change that
    /// failed before anything was sent, audited with its reason.
    Failed(Failure),
    /// The request names nothing the router has a change for: answered 404, like a page
    /// that does not exist, and not audited.
    Missing,
    /// The router already has the submitted values: nothing is sent, answered as such in
    /// the outcome region, audited `unchanged`.
    Unchanged,
}

impl From<Invalid> for Rejected {
    fn from(invalid: Invalid) -> Self {
        Self::Invalid(invalid)
    }
}

impl From<Failure> for Rejected {
    fn from(failure: Failure) -> Self {
        Self::Failed(failure)
    }
}
