//! Failures in the user's words: change-workflow errors, router errors and catalog
//! findings, each mapped to a localized message and a stable audit outcome id.
//!
//! A router error status keeps only the router's message text for the "router said"
//! block; request bodies and anything else the request carried never reach a page.

use fluent_bundle::FluentArgs;
use kcc_app::workflow::WorkflowError;
use kcc_catalog::{HttpMethod, ValidationIssue};
use kcc_domain::DomainError;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::RciError;

use super::{family::Family, outcome::Failure};

/// What a failure says about the request beyond its audit id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureKind {
    /// The role may not make the change: the page answers 403.
    Forbidden,
    /// Any other failure, answered where the page shows it.
    Failed,
}

/// The failure of a change-workflow error, in `family`'s words.
pub(crate) fn workflow_failure(family: Family, locale: Locale, error: &WorkflowError) -> Failure {
    match error {
        WorkflowError::Rci(rci) => rci_failure(family, locale, rci),
        WorkflowError::RouterBusy { actor } => {
            let mut args = FluentArgs::new();
            args.set("user", actor.clone());
            Failure::new(tr(locale, keys::WEB_SAVE_BUSY, Some(&args)), "busy")
        }
        WorkflowError::Conflict { agent: _ } => {
            Failure::new(tr(locale, family.conflict(), None), "conflict")
        }
        WorkflowError::RecoveryTimerInUse => {
            Failure::new(tr(locale, keys::MANAGEMENT_TIMER_IN_USE, None), "conflict")
        }
        WorkflowError::Unowned => {
            Failure::new(tr(locale, keys::WEB_BRACKET_UNOWNED, None), "failed")
        }
        WorkflowError::PermissionDenied { router: _ } => Failure::forbidden(locale),
        WorkflowError::CatalogValidation { issues } => Failure::new(
            issues
                .iter()
                .map(|issue| issue_sentence(locale, issue))
                .collect::<Vec<_>>()
                .join(" "),
            "validation_failed",
        ),
        WorkflowError::VerificationFailed { field } => {
            let mut args = FluentArgs::new();
            args.set("field", field.clone());
            Failure::new(
                tr(locale, keys::WEB_KIT_VERIFICATION_FAILED, Some(&args)),
                "verification_failed",
            )
        }
        WorkflowError::State(_)
        | WorkflowError::Registry(_)
        | WorkflowError::Backup(_)
        | WorkflowError::Audit(_)
        | WorkflowError::InvalidResponse
        | WorkflowError::UnsupportedFirmware
        | WorkflowError::UndecodableConfig
        | WorkflowError::UnexpectedBody
        | WorkflowError::Refused(_)
        | WorkflowError::SaveTimeout
        | WorkflowError::SecretCommand(_)
        | _ => {
            tracing::error!(%error, "change failed");
            Failure::new(tr(locale, family.failed(), None), "failed")
        }
    }
}

/// The failure of a router error, in `family`'s words; an error status carries the
/// router's message, nothing else.
pub(crate) fn rci_failure(family: Family, locale: Locale, error: &RciError) -> Failure {
    match error {
        RciError::Rci {
            pointer: _,
            code: _,
            ident: _,
            message,
        } => Failure::new(tr(locale, family.rejected(), None), "rci_error")
            .with_router_said(vec![message.clone()]),
        RciError::Transport(_) | RciError::Policy => {
            Failure::new(tr(locale, family.unreachable(), None), "unreachable")
        }
        RciError::Timeout => Failure::new(tr(locale, keys::ERRORS_TIMEOUT, None), "timeout"),
        RciError::NotFound => Failure::new(tr(locale, family.not_found(), None), "rci_error"),
        RciError::Auth(_) => Failure::new(tr(locale, keys::ERRORS_ROUTER_AUTH, None), "rci_error"),
        RciError::Http { status: _ }
        | RciError::MethodNotAllowed
        | RciError::BodyTooLarge
        | RciError::Decode(_)
        | RciError::Validation
        | _ => {
            tracing::debug!(?error, "router request failed");
            Failure::new(tr(locale, family.failed(), None), "rci_error")
        }
    }
}

/// The failure of planning a change with a domain, in `family`'s words: catalog findings
/// name their fields, a router error keeps the router's message.
pub(crate) fn plan_failure(family: Family, locale: Locale, error: &DomainError) -> Failure {
    match error {
        DomainError::Validation { issues } => Failure::new(
            issues
                .iter()
                .map(|issue| issue_sentence(locale, issue))
                .collect::<Vec<_>>()
                .join(" "),
            "validation_failed",
        ),
        DomainError::Rci(rci) => rci_failure(family, locale, rci),
        DomainError::PermissionDenied => Failure::forbidden(locale),
        DomainError::EntwareDriveInUse => Failure::new(
            tr(locale, keys::DOMAINS_ENTWARE_DRIVE_IN_USE, None),
            "entware_drive_in_use",
        ),
        DomainError::InvalidResponse
        | DomainError::ConfirmationMismatch
        | DomainError::StaticLeaseOutsidePool
        | DomainError::StaticLeaseAddressInUse
        | DomainError::ProtectedAccount
        | DomainError::InvalidCliToken
        | DomainError::ConfirmationRequired
        | _ => {
            tracing::warn!(%error, "change could not be planned");
            Failure::new(tr(locale, family.failed(), None), "failed")
        }
    }
}

/// A localized sentence for one catalog finding, naming its field.
pub(crate) fn issue_sentence(locale: Locale, issue: &ValidationIssue) -> String {
    let mut args = FluentArgs::new();
    let key = match issue {
        ValidationIssue::UnknownPath { path } => {
            args.set("path", path.clone());
            keys::WEB_EXPLORER_ISSUE_UNKNOWN_PATH
        }
        ValidationIssue::MethodNotAllowed { method } => {
            args.set("method", method_name(*method));
            keys::WEB_EXPLORER_ISSUE_METHOD
        }
        ValidationIssue::ExpectedObject { field } => {
            args.set("field", display_field(field));
            keys::WEB_EXPLORER_ISSUE_OBJECT
        }
        ValidationIssue::UnknownField {
            field,
            suggestion: Some(suggestion),
        } => {
            args.set("field", display_field(field));
            args.set("suggestion", suggestion.clone());
            keys::WEB_EXPLORER_ISSUE_SUGGESTION
        }
        ValidationIssue::UnknownField {
            field,
            suggestion: None,
        } => {
            args.set("field", display_field(field));
            keys::WEB_EXPLORER_ISSUE_UNKNOWN_FIELD
        }
        ValidationIssue::InvalidValue { field } => {
            args.set("field", display_field(field));
            keys::WEB_EXPLORER_ISSUE_VALUE
        }
        ValidationIssue::NoPrefixUnsupported => keys::WEB_EXPLORER_ISSUE_NO,
        ValidationIssue::InvalidCliSyntax => keys::WEB_EXPLORER_ISSUE_CLI_SYNTAX,
        ValidationIssue::UnsupportedCliSyntax { path } => {
            args.set("path", path.clone());
            keys::WEB_EXPLORER_ISSUE_CLI_FORM
        }
        ValidationIssue::RawAuthorizationRequired | _ => keys::WEB_EXPLORER_ISSUE_RAW,
    };
    tr(locale, key, Some(&args))
}

/// The HTTP method name.
pub(crate) const fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Delete | _ => "DELETE",
    }
}

/// A field path as people read it; the root of a body is shown as `/`.
fn display_field(field: &str) -> String {
    if field.is_empty() {
        "/".to_owned()
    } else {
        field.to_owned()
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use kcc_i18n::locale::Locale;
    use kcc_rci::RciResponse;
    use serde_json::json;

    use super::rci_failure;
    use crate::page_kit::{family::Family, outcome::Outcome};

    #[test]
    fn a_router_error_keeps_only_the_message_text() -> Result<(), Box<dyn Error>> {
        let answer = json!({"system": {"hostname": "draft", "status": [{
            "status": "error", "code": "7405600", "ident": "Core::Configurator",
            "message": "invalid host name"}]}});
        let Err(error) = RciResponse::from_value(answer) else {
            return Err("an error status must be an error".into());
        };
        let outcome = Outcome::failed(rci_failure(Family::Commands, Locale::En, &error));
        assert_eq!(outcome.router_said(), ["invalid host name"], "message only");
        assert_eq!(outcome.audit(), "rci_error", "audit id");
        assert_eq!(outcome.tone(), "error", "tone");
        Ok(())
    }
}
