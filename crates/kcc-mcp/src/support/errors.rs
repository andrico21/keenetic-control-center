//! Stable mapping of application, router, and domain failures onto MCP error codes.

use core::fmt;

use kcc_app::workflow::WorkflowError;
use kcc_domain::DomainError;
use kcc_rci::{RciBody, RciError, RciResponse};
use rmcp::ErrorData;
use serde_json::{Value, json};

use crate::McpFailure;

/// Maps a protected workflow failure.
pub(crate) fn map_workflow(error: WorkflowError) -> McpFailure {
    tracing::warn!(error = ?error, "MCP change workflow failed");
    match error {
        WorkflowError::PermissionDenied { router: _ } => McpFailure::Forbidden,
        WorkflowError::CatalogValidation { issues: _ } => McpFailure::ValidationFailed,
        WorkflowError::VerificationFailed { field } => McpFailure::VerificationFailed { field },
        WorkflowError::Conflict { agent: _ } | WorkflowError::RouterBusy { actor: _ } => {
            McpFailure::Conflict
        }
        WorkflowError::Rci(rci) => map_rci(&rci),
        WorkflowError::State(_)
        | WorkflowError::Registry(_)
        | WorkflowError::Backup(_)
        | WorkflowError::Audit(_)
        | WorkflowError::InvalidResponse
        | WorkflowError::SaveTimeout
        | _ => McpFailure::Internal,
    }
}

/// Maps a router transport or protocol failure.
pub(crate) fn map_rci(error: &RciError) -> McpFailure {
    tracing::warn!(error = ?error, "MCP RCI request failed");
    match error {
        RciError::Transport | RciError::Timeout | RciError::Policy => McpFailure::RouterUnreachable,
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
        RciError::BodyTooLarge | RciError::Decode | _ => McpFailure::Internal,
    }
}

/// Maps a curated domain failure.
pub(crate) fn map_domain(error: DomainError) -> McpFailure {
    match error {
        DomainError::Rci(rci) => map_rci(&rci),
        DomainError::Workflow(workflow) => map_workflow(workflow),
        DomainError::Validation { issues } => {
            tracing::warn!(?issues, "MCP domain validation failed");
            McpFailure::ValidationFailed
        }
        DomainError::ConfirmationMismatch | DomainError::ConfirmationRequired => {
            McpFailure::InvalidArguments
        }
        DomainError::StaticLeaseOutsidePool
        | DomainError::StaticLeaseAddressInUse
        | DomainError::InvalidCliToken => McpFailure::ValidationFailed,
        DomainError::ProtectedAccount | DomainError::PermissionDenied => McpFailure::Forbidden,
        DomainError::SafetyAbort | DomainError::RouteCountMismatch => McpFailure::Conflict,
        DomainError::InvalidResponse | _ => {
            tracing::warn!(error = ?error, "MCP domain operation failed");
            McpFailure::Internal
        }
    }
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
                "level": format!("{:?}", item.status).to_ascii_lowercase(),
                "code": item.code,
                "ident": item.ident
            })
        })
        .collect()
}

/// Converts a stable failure into protocol error data.
pub(crate) fn failure_error(failure: McpFailure) -> ErrorData {
    ErrorData::invalid_params(failure.code(), None)
}

/// Logs an internal failure and returns an opaque protocol error.
pub(crate) fn internal_error(context: &str, error: &dyn fmt::Debug) -> ErrorData {
    tracing::error!(context, ?error, "MCP internal request failure");
    ErrorData::internal_error("internal", None)
}
