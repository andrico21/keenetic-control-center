//! Hash-chained audit records for MCP tool failures that reach kcc handlers, and for the
//! successes of tools whose action leaves no change-workflow entry of its own.

use std::time::{SystemTime, UNIX_EPOCH};

use kcc_app::audit::{Actor, ActorKind, Attempt, AuditEvent, receipt::AUDIT_WAIT};
use rmcp_server_kit::rbac::current_identity;
use serde_json::Value;

use super::{
    call::current_request_id,
    shape::{FailureContext, noting},
};
use crate::{KccMcp, McpFailure};

/// The success of a tool whose action the change workflow does not audit: a backup, a
/// preset, a job.
pub(crate) struct Success {
    /// The tool, recorded as action `mcp.<tool>` like the tool's failures.
    tool: &'static str,
    /// The router the action addressed.
    router: Option<String>,
    /// The object acted on.
    target: Option<String>,
    /// Identifiers of the object, never values a client typed.
    params: Value,
}

impl Success {
    /// The success of `tool`, with no router, target or parameters.
    pub(crate) const fn new(tool: &'static str) -> Self {
        Self {
            tool,
            router: None,
            target: None,
            params: Value::Null,
        }
    }

    /// The router the action addressed.
    pub(crate) fn on_router(self, router: &str) -> Self {
        Self {
            router: Some(router.to_owned()),
            ..self
        }
    }

    /// The object acted on.
    pub(crate) fn with_target(self, target: String) -> Self {
        Self {
            target: Some(target),
            ..self
        }
    }

    /// Identifiers of the object.
    pub(crate) fn with_params(self, params: Value) -> Self {
        Self { params, ..self }
    }

    /// Appends the entry under the call's request id and waits for it a bounded time;
    /// returns `result`, marked `audit_pending` while the entry is still queued. A failed
    /// append is logged and the action stands.
    // NOT cancel-safe: once queued, the audit writer may append after this future is dropped.
    pub(crate) async fn record(self, server: &KccMcp, result: Value) -> Value {
        let Some(audit) = &server.audit else {
            return result;
        };
        let Self {
            tool,
            router,
            target,
            params,
        } = self;
        let mut event = AuditEvent::new(timestamp(), actor(), format!("mcp.{tool}"))
            .with_params(params)
            .with_result("success".to_owned(), current_request_id());
        if let Some(name) = router {
            event = event.with_router(name);
        }
        if let Some(object) = target {
            event = event.with_target(object);
        }
        let receipt = match audit.submit(event) {
            Ok(queued) => queued.settle(AUDIT_WAIT).await,
            Err(error) => Err(error),
        };
        match receipt {
            Ok(receipt) => noting(result, &receipt),
            Err(error) => {
                tracing::warn!(error = ?error, tool, "MCP success audit append failed");
                result
            }
        }
    }
}

/// The MCP principal of the current call.
fn actor() -> Actor {
    Actor::new(
        ActorKind::Mcp,
        current_identity().unwrap_or_else(|| "stdio".to_owned()),
    )
}

/// Seconds since the Unix epoch.
fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

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
    let event = AuditEvent::attempt(
        timestamp(),
        actor(),
        format!("mcp.{}", context.tool()),
        context.router().map(str::to_owned),
        attempt,
    )
    .with_request_id(request_id.to_owned());
    if let Err(audit_error) = audit.append(event).await {
        tracing::warn!(error = ?audit_error, tool = context.tool(), "MCP failure audit append failed");
    }
}
