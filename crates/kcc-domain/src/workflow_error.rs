//! The one mapping of a domain failure met inside a change onto the workflow's words.

use kcc_app::workflow::{WorkflowError, refusal::Refusal};

use crate::{DomainError, mesh::RebootError, segments::SegmentError, system::FactoryResetError};

/// The read-back field a firewall rule verification names.
const FIREWALL_RULE_FIELD: &str = "/interface/ip/access-group";

impl From<DomainError> for WorkflowError {
    /// The one mapping of a domain failure met inside a change onto the workflow's words:
    /// catalog findings, router errors, permission and read-back failures keep their kind,
    /// and the planning layer's own refusals keep why they refused.
    #[inline]
    fn from(error: DomainError) -> Self {
        match error {
            DomainError::Workflow(workflow) => workflow,
            DomainError::Rci(rci) => Self::Rci(rci),
            DomainError::Validation { issues } => Self::CatalogValidation { issues },
            DomainError::PermissionDenied => Self::PermissionDenied {
                router: String::new(),
            },
            DomainError::FirewallVerificationFailed => Self::VerificationFailed {
                field: FIREWALL_RULE_FIELD.to_owned(),
            },
            DomainError::InvalidResponse => Self::UnexpectedBody,
            DomainError::StaticLeaseOutsidePool
            | DomainError::StaticLeaseAddressInUse
            | DomainError::InvalidCliToken
            | DomainError::FirewallRuleAbsent => Self::Refused(Refusal::InvalidInput),
            DomainError::ConfirmationMismatch => Self::Refused(Refusal::ConfirmationMismatch),
            DomainError::ConfirmationRequired => Self::Refused(Refusal::ConfirmationRequired),
            DomainError::ProtectedAccount => Self::Refused(Refusal::ProtectedAccount),
            DomainError::SafetyAbort | DomainError::RouteCountMismatch => {
                Self::Refused(Refusal::Unsafe)
            }
        }
    }
}

impl From<FactoryResetError> for WorkflowError {
    /// The workflow's words for a refused reset, through the domain's one mapping.
    #[inline]
    fn from(error: FactoryResetError) -> Self {
        match error {
            FactoryResetError::ConfirmationMismatch => Self::Refused(Refusal::ConfirmationMismatch),
            FactoryResetError::Domain(domain) => domain.into(),
            FactoryResetError::Workflow(workflow) => workflow,
        }
    }
}

impl From<RebootError> for WorkflowError {
    /// The workflow's words for a failed member restart, through the domain's one mapping.
    #[inline]
    fn from(error: RebootError) -> Self {
        match error {
            RebootError::ConfirmationMismatch => Self::Refused(Refusal::ConfirmationMismatch),
            RebootError::Domain(domain) => domain.into(),
            RebootError::Workflow(workflow) => workflow,
        }
    }
}

impl From<SegmentError> for WorkflowError {
    /// The workflow's words for a failed segment change: the failed step's own error, or
    /// the planning failure through the domain's one mapping.
    #[inline]
    fn from(error: SegmentError) -> Self {
        match error {
            SegmentError::Domain(domain) => domain.into(),
            SegmentError::StepFailed { step: _, source }
            | SegmentError::RollbackFailed {
                step: _,
                rollback_step: _,
                source,
            } => *source,
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions are not rendered API documentation"
)]
mod tests {
    use kcc_app::workflow::{WorkflowError, refusal::Refusal};
    use kcc_catalog::ValidationIssue;

    use super::FIREWALL_RULE_FIELD;
    use crate::DomainError;

    /// W3-06: a domain failure keeps its kind inside a change.
    ///
    /// Every front end uses this one mapping: catalog findings, a permission refusal, a
    /// read-back failure and a planning refusal are not turned into an invalid response.
    #[test]
    fn a_domain_failure_keeps_its_kind_inside_a_change() {
        let findings = vec![ValidationIssue::InvalidCliSyntax];
        assert!(matches!(
            WorkflowError::from(DomainError::Validation { issues: findings.clone() }),
            WorkflowError::CatalogValidation { issues } if issues == findings
        ));
        assert!(matches!(
            WorkflowError::from(DomainError::PermissionDenied),
            WorkflowError::PermissionDenied { router: _ }
        ));
        assert!(matches!(
            WorkflowError::from(DomainError::FirewallVerificationFailed),
            WorkflowError::VerificationFailed { field } if field == FIREWALL_RULE_FIELD
        ));
        assert!(matches!(
            WorkflowError::from(DomainError::ProtectedAccount),
            WorkflowError::Refused(Refusal::ProtectedAccount)
        ));
    }
}
