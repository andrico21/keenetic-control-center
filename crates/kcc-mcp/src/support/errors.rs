//! Stable mapping of application, router, and domain failures onto MCP error codes.

use core::fmt;

use kcc_app::workflow::{WorkflowError, refusal::Refusal};
use kcc_domain::{
    DomainError,
    configuration::{
        bracket::ArmedFate,
        recovery::{self, Fate},
    },
};
use kcc_rci::{RciBody, RciError, RciResponse};
use rmcp::ErrorData;
use serde_json::{Value, json};

use super::names;
use crate::McpFailure;

/// Maps a failed bracket: an armed fate to its code, a refused arm whose disarm was accepted
/// to a failure that says nothing was applied, otherwise the original error.
pub(crate) fn map_recovery(error: recovery::Failure<McpFailure>) -> McpFailure {
    match error.outcome() {
        Fate::Armed(fate) => armed(fate),
        Fate::NotApplied => McpFailure::NotApplied {
            cause: Box::new(error.into_source()),
        },
        // A fate this version does not know keeps the original error; a timer somebody
        // else armed is the source's own conflict.
        Fate::Settled | Fate::TimerInUse | _ => error.into_source(),
    }
}

/// The code of a failure that may have left the recovery timer armed.
pub(crate) const fn armed(fate: ArmedFate) -> McpFailure {
    match fate {
        ArmedFate::NotSent => McpFailure::ManagementNotSentFailSafeArmed,
        ArmedFate::Applied => McpFailure::ManagementAppliedFailSafeArmed,
        ArmedFate::Saved => McpFailure::ManagementSavedFailSafeArmed,
        ArmedFate::Unknown | _ => McpFailure::ManagementOutcomeUnknownFailSafeArmed,
    }
}

impl From<WorkflowError> for McpFailure {
    #[inline]
    fn from(error: WorkflowError) -> Self {
        map_workflow(error)
    }
}

/// Maps a protected workflow failure: the one mapping every MCP change error goes through.
pub(crate) fn map_workflow(error: WorkflowError) -> McpFailure {
    tracing::warn!(error = ?error, "MCP change workflow failed");
    match error {
        WorkflowError::PermissionDenied { router: _ } => McpFailure::Forbidden,
        WorkflowError::CatalogValidation { issues: _ }
        | WorkflowError::SecretCommand(_)
        | WorkflowError::UnsupportedFirmware => McpFailure::ValidationFailed,
        WorkflowError::VerificationFailed { field } => McpFailure::VerificationFailed { field },
        WorkflowError::Conflict { agent: _ }
        | WorkflowError::RouterBusy { actor: _ }
        | WorkflowError::RecoveryTimerInUse => McpFailure::Conflict,
        WorkflowError::Rci(rci) => map_rci(&rci),
        WorkflowError::Refused(refusal) => map_refusal(refusal),
        // The workflow's enum is not exhaustive outside its crate: an error this version
        // does not know is internal.
        WorkflowError::State(_)
        | WorkflowError::Registry(_)
        | WorkflowError::Backup(_)
        | WorkflowError::Audit(_)
        | WorkflowError::InvalidResponse
        | WorkflowError::UndecodableConfig
        | WorkflowError::UnexpectedBody
        | WorkflowError::SaveTimeout
        | WorkflowError::Unowned
        | _ => McpFailure::Internal,
    }
}

/// Maps a change the planning layer refused on its own.
const fn map_refusal(refusal: Refusal) -> McpFailure {
    match refusal {
        Refusal::InvalidInput => McpFailure::ValidationFailed,
        Refusal::ConfirmationMismatch | Refusal::ConfirmationRequired => {
            McpFailure::InvalidArguments
        }
        Refusal::ProtectedAccount => McpFailure::Forbidden,
        Refusal::Unsafe => McpFailure::Conflict,
        // A refusal this version does not know is internal.
        _ => McpFailure::Internal,
    }
}

/// Maps a router transport or protocol failure.
pub(crate) fn map_rci(error: &RciError) -> McpFailure {
    tracing::warn!(error = ?error, "MCP RCI request failed");
    match error {
        RciError::Transport(_) | RciError::Timeout | RciError::Policy => {
            McpFailure::RouterUnreachable
        }
        RciError::Auth(_)
        | RciError::Http { status: _ }
        | RciError::Rci {
            pointer: _,
            code: _,
            ident: _,
            message: _,
        }
        | RciError::NotFound
        | RciError::MethodNotAllowed => McpFailure::RouterRejected,
        RciError::Validation => McpFailure::ValidationFailed,
        RciError::BodyTooLarge | RciError::Decode(_) | _ => McpFailure::Internal,
    }
}

/// Maps a curated domain failure through the domain's one mapping onto the workflow's words.
pub(crate) fn map_domain(error: DomainError) -> McpFailure {
    map_workflow(WorkflowError::from(error))
}

/// Converts a router body into its stable JSON projection.
pub(crate) fn rci_body_value(body: RciBody) -> Value {
    match body {
        RciBody::Json(response) => json!({
            "value": response.value,
            "statuses": statuses(&response)
        }),
        RciBody::Text(text) => json!({ "text": text, "statuses": [] }),
        _ => json!({ "error": "internal" }),
    }
}

/// Projects router status messages without free-form text.
pub(crate) fn statuses(response: &RciResponse) -> Vec<Value> {
    response
        .statuses
        .iter()
        .map(|(pointer, item)| {
            json!({
                "pointer": pointer.as_str(),
                "level": names::level(item.status),
                "code": item.code,
                "ident": item.ident
            })
        })
        .collect()
}

/// Converts a stable failure into protocol error data.
#[expect(
    clippy::needless_pass_by_value,
    reason = "used as a `map_err` callback, which hands over the failure by value"
)]
pub(crate) fn failure_error(failure: McpFailure) -> ErrorData {
    ErrorData::invalid_params(failure.code(), None)
}

/// Logs an internal failure and returns an opaque protocol error.
pub(crate) fn internal_error(context: &str, error: &dyn fmt::Debug) -> ErrorData {
    tracing::error!(context, ?error, "MCP internal request failure");
    ErrorData::internal_error("internal", None)
}
