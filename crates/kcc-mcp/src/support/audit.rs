//! Hash-chained audit records for MCP tool failures that reach kcc handlers.

use std::time::{SystemTime, UNIX_EPOCH};

use kcc_app::audit::{Actor, ActorKind, AuditEvent};
use rmcp_server_kit::rbac::current_identity;
use serde_json::{Value, json};

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
    let (outcome, params) = match error {
        McpFailure::Forbidden => ("forbidden", json!({"reason": error.code()})),
        McpFailure::ConfirmRequired
        | McpFailure::DestructiveDisabled
        | McpFailure::ValidationFailed
        | McpFailure::UnverifiedFirmwareTier => ("refused", json!({"reason": error.code()})),
        McpFailure::RouterUnreachable
        | McpFailure::BatchFailSafeArmed {
            applied: _,
            completion: _,
        }
        | McpFailure::ManagementAppliedFailSafeArmed
        | McpFailure::ManagementOutcomeUnknownFailSafeArmed
        | McpFailure::RouterRejected
        | McpFailure::VerificationFailed { field: _ }
        | McpFailure::Conflict
        | McpFailure::Internal
            if !context.read_only() =>
        {
            let mut params = json!({"error": error.code()});
            if matches!(
                error,
                McpFailure::ManagementAppliedFailSafeArmed
                    | McpFailure::BatchFailSafeArmed {
                        applied: _,
                        completion: _
                    }
                    | McpFailure::ManagementOutcomeUnknownFailSafeArmed
            ) && let Value::Object(object) = &mut params
            {
                drop(object.insert("fail_safe_armed".to_owned(), json!(true)));
            }
            ("failed", params)
        }
        McpFailure::InvalidArguments
        | McpFailure::BatchFailSafeArmed {
            applied: _,
            completion: _,
        }
        | McpFailure::ManagementAppliedFailSafeArmed
        | McpFailure::ManagementOutcomeUnknownFailSafeArmed
        | McpFailure::RouterUnreachable
        | McpFailure::RouterRejected
        | McpFailure::VerificationFailed { field: _ }
        | McpFailure::Conflict
        | McpFailure::Internal => return,
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let mut event = AuditEvent::new(
        timestamp,
        Actor::new(
            ActorKind::Mcp,
            current_identity().unwrap_or_else(|| "stdio".to_owned()),
        ),
        format!("mcp.{}", context.tool()),
    )
    .with_params(params)
    .with_result(outcome.to_owned(), request_id.to_owned());
    if let Some(router) = context.router() {
        event = event.with_router(router.to_owned());
    }
    if let Err(audit_error) = audit.append(event).await {
        tracing::warn!(error = ?audit_error, tool = context.tool(), "MCP failure audit append failed");
    }
}
