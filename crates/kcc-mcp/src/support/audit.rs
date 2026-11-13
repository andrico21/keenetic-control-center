//! Hash-chained audit records for MCP tool failures that reach kcc handlers.

use std::time::{SystemTime, UNIX_EPOCH};

use kcc_app::audit::{Actor, ActorKind, Attempt, AuditEvent};
use rmcp_server_kit::rbac::current_identity;

use super::shape::FailureContext;
use crate::{KccMcp, McpFailure};

/// Appends one refusal or failed-change entry without exposing tool arguments.
// NOT cancel-safe: once queued, the audit writer may append after this future is dropped.
pub(crate) async fn failure(
    server: &KccMcp,
    context: FailureContext<'_>,
    error: &McpFailure,
    request_id: &str,
) {
    let Some(audit) = &server.audit else {
        return;
    };
    let error = if let McpFailure::NotApplied { cause } = error {
        cause.as_ref()
    } else {
        error
    };
    let attempt = match error {
        McpFailure::Forbidden => Attempt::Forbidden,
        McpFailure::ConfirmRequired
        | McpFailure::DestructiveDisabled
        | McpFailure::ValidationFailed
        | McpFailure::RouterModeUnknown
        | McpFailure::UnverifiedFirmwareTier => Attempt::Refused {
            reason: error.code(),
        },
        McpFailure::RouterUnreachable
        | McpFailure::BatchFailSafeArmed {
            applied: _,
            completion: _,
        }
        | McpFailure::ManagementAppliedFailSafeArmed
        | McpFailure::ManagementSavedFailSafeArmed
        | McpFailure::ManagementOutcomeUnknownFailSafeArmed
        | McpFailure::ManagementNotSentFailSafeArmed
        | McpFailure::ManagementAppliedNotSaved
        | McpFailure::ManagementNotCommittedFailSafeArmed
        | McpFailure::RouterRejected
        | McpFailure::VerificationFailed { field: _ }
        | McpFailure::Conflict
        | McpFailure::JobUnavailable
        | McpFailure::Internal
        | McpFailure::MigrationRollbackRestarting
            if !context.read_only() =>
        {
            Attempt::Failed {
                error: error.code(),
                fail_safe_armed: matches!(
                    error,
                    McpFailure::ManagementAppliedFailSafeArmed
                        | McpFailure::ManagementSavedFailSafeArmed
                        | McpFailure::BatchFailSafeArmed {
                            applied: _,
                            completion: _
                        }
                        | McpFailure::ManagementOutcomeUnknownFailSafeArmed
                        | McpFailure::ManagementNotSentFailSafeArmed
                        | McpFailure::ManagementNotCommittedFailSafeArmed
                ),
            }
        }
        McpFailure::InvalidArguments
        | McpFailure::BatchFailSafeArmed {
            applied: _,
            completion: _,
        }
        | McpFailure::ManagementAppliedFailSafeArmed
        | McpFailure::ManagementSavedFailSafeArmed
        | McpFailure::ManagementOutcomeUnknownFailSafeArmed
        | McpFailure::ManagementNotSentFailSafeArmed
        | McpFailure::ManagementAppliedNotSaved
        | McpFailure::ManagementNotCommittedFailSafeArmed
        | McpFailure::RouterUnreachable
        | McpFailure::RouterRejected
        | McpFailure::VerificationFailed { field: _ }
        | McpFailure::Conflict
        | McpFailure::JobUnavailable
        | McpFailure::Internal
        | McpFailure::MigrationRollbackRestarting
        | McpFailure::NotApplied { cause: _ } => return,
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let event = AuditEvent::attempt(
        timestamp,
        Actor::new(
            ActorKind::Mcp,
            current_identity().unwrap_or_else(|| "stdio".to_owned()),
        ),
        format!("mcp.{}", context.tool()),
        context.router().map(str::to_owned),
        attempt,
    )
    .with_request_id(request_id.to_owned());
    if let Err(audit_error) = audit.append(event).await {
        tracing::warn!(error = ?audit_error, tool = context.tool(), "MCP failure audit append failed");
    }
}
