//! One tool call: its correlation id and `mcp_tool` span around the work, and the
//! protocol result of its outcome.

use kcc_app::audit::request_id;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::{Value, json};
use tracing::Instrument as _;

use super::shape::{FailureContext, shape};
use crate::{KccMcp, McpFailure};

tokio::task_local! {
    /// The correlation id of the tool call the current task serves.
    static REQUEST_ID: String;
}

/// A fresh request correlation id.
pub(crate) fn next_request_id() -> String {
    request_id::next("mcp")
}

/// The correlation id of the tool call being served; a fresh one outside a call.
pub(crate) fn current_request_id() -> String {
    REQUEST_ID
        .try_with(Clone::clone)
        .unwrap_or_else(|_outside| next_request_id())
}

/// Runs a tool's `work` under a fresh correlation id, inside an `mcp_tool` span carrying
/// it, and converts the outcome into a protocol result returning that id on failure.
// NOT cancel-safe: the work may change router or local state, and a queued audit append
// may complete after cancellation.
pub(crate) async fn finish_with_context<Work>(
    server: &KccMcp,
    context: FailureContext<'_>,
    work: Work,
) -> CallToolResult
where
    Work: Future<Output = Result<Value, McpFailure>>,
{
    let request_id = next_request_id();
    let span = tracing::info_span!("mcp_tool", request_id = %request_id, tool = context.tool());
    let call = async {
        let result = work.await;
        answer(server, context, result, &request_id).await
    };
    REQUEST_ID
        .scope(request_id.clone(), call)
        .instrument(span)
        .await
}

/// The protocol result of one tool outcome; a failure is logged, audited and answered
/// with `request_id`.
// NOT cancel-safe: a queued audit append may complete after cancellation.
async fn answer(
    server: &KccMcp,
    context: FailureContext<'_>,
    result: Result<Value, McpFailure>,
    request_id: &str,
) -> CallToolResult {
    match result.and_then(|value| shape(server, value, Some(request_id))) {
        Ok(text) => CallToolResult::success(vec![ContentBlock::text(text)]),
        Err(error) => {
            tracing::warn!(request_id, code = error.code(), "MCP tool request failed");
            super::audit::failure(server, context, &error, request_id).await;
            let cause = if let McpFailure::NotApplied { cause } = &error {
                cause.as_ref()
            } else {
                &error
            };
            let mut reply = if let McpFailure::BatchFailSafeArmed {
                applied: _,
                completion,
            } = &error
            {
                *completion.clone()
            } else {
                json!({})
            };
            if let Value::Object(object) = &mut reply {
                drop(object.insert("error".to_owned(), json!(error.code())));
                drop(object.insert("request_id".to_owned(), json!(request_id)));
            }
            let recovery_message = match &error {
                McpFailure::BatchFailSafeArmed {
                    applied: true,
                    completion: _,
                }
                | McpFailure::ManagementAppliedFailSafeArmed => {
                    Some(keys::MANAGEMENT_DISARM_FAILED)
                }
                McpFailure::BatchFailSafeArmed {
                    applied: false,
                    completion: _,
                }
                | McpFailure::ManagementOutcomeUnknownFailSafeArmed => {
                    Some(keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED)
                }
                McpFailure::ManagementSavedFailSafeArmed => Some(keys::FINISH_SAVED_ARMED),
                McpFailure::ManagementNotSentFailSafeArmed => Some(keys::MANAGEMENT_NOT_SENT_ARMED),
                McpFailure::MigrationRollbackRestarting => Some(keys::MIGRATE_ROLLBACK_SAVED),
                McpFailure::NotApplied { cause: _ } => Some(keys::MANAGEMENT_NOT_APPLIED),
                McpFailure::ManagementAppliedNotSaved => Some(keys::MIGRATE_COMMITTED_NOT_SAVED),
                McpFailure::ManagementNotCommittedFailSafeArmed => {
                    Some(keys::MIGRATE_COMMIT_NOT_SENT_ARMED)
                }
                McpFailure::InvalidArguments
                | McpFailure::Forbidden
                | McpFailure::ConfirmRequired
                | McpFailure::DestructiveDisabled
                | McpFailure::RouterUnreachable
                | McpFailure::RouterRejected
                | McpFailure::RouterModeUnknown
                | McpFailure::ValidationFailed
                | McpFailure::VerificationFailed { field: _ }
                | McpFailure::Conflict
                | McpFailure::JobUnavailable
                | McpFailure::Internal
                | McpFailure::UnverifiedFirmwareTier => None,
            };
            if let Some(key) = recovery_message
                && let Value::Object(object) = &mut reply
            {
                drop(object.insert("message".to_owned(), json!(tr(Locale::En, key, None))));
            }
            if let (McpFailure::VerificationFailed { field }, Value::Object(object)) =
                (cause, &mut reply)
            {
                drop(object.insert("field".to_owned(), Value::String(field.clone())));
            }
            let text = shape(server, reply, Some(request_id))
                .unwrap_or_else(|_error| "{\"error\":\"internal\"}".to_owned());
            CallToolResult::error(vec![ContentBlock::text(text)])
        }
    }
}

/// Runs a router-independent tool's `work` like [`finish_with_context`].
// NOT cancel-safe: as `finish_with_context`.
pub(crate) async fn finish<Work>(
    server: &KccMcp,
    tool: &'static str,
    read_only: bool,
    work: Work,
) -> CallToolResult
where
    Work: Future<Output = Result<Value, McpFailure>>,
{
    finish_with_context(server, FailureContext::new(tool, read_only, None), work).await
}
