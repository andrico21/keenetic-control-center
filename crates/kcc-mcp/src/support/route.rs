//! Dynamic RMCP routes for registry-generated tools and their progress reporting.

use alloc::sync::Arc;
use core::pin::Pin;

use rmcp::{
    handler::server::{common::schema_for_type, router::tool::ToolRoute, tool::ToolCallContext},
    model::{JsonObject, ProgressNotificationParam, ProgressToken, Tool},
    service::{Peer, RequestContext, RoleServer},
};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{
    call::finish_with_context, scrub::scrub_text, shape::FailureContext, validate::parse_cursor,
};
use crate::{KccMcp, McpFailure, registry::definitions::ToolDescription};

/// The description of the `confirm` input of every curated write tool.
const CONFIRM_DOC: &str = "Confirmation, required when the change touches management or is destructive; without it the call is refused with confirm_required.";

/// The boxed outcome of one dynamic tool call.
pub(crate) type ToolFuture<'call> =
    Pin<Box<dyn Future<Output = Result<Value, McpFailure>> + Send + 'call>>;

/// Progress notifications for a call whose client supplied a progress token.
#[derive(Clone, Debug)]
pub(crate) struct Progress {
    /// Session peer that receives notifications.
    peer: Peer<RoleServer>,
    /// The client's token.
    token: ProgressToken,
    /// Whether client identifiers are pseudonymized in messages.
    redact_clients: bool,
}

impl Progress {
    /// Captures the request's progress token, when present.
    pub(crate) fn from_request(
        context: &RequestContext<RoleServer>,
        redact_clients: bool,
    ) -> Option<Self> {
        context.meta.get_progress_token().map(|token| Self {
            peer: context.peer.clone(),
            token,
            redact_clients,
        })
    }

    /// Sends one notification; a closed session only loses the notification.
    pub(crate) async fn notify(&self, progress: u32, text: String) {
        let message = if self.redact_clients {
            scrub_text(&text)
        } else {
            text
        };
        let param = ProgressNotificationParam::new(self.token.clone(), f64::from(progress))
            .with_message(message);
        if let Err(error) = self.peer.notify_progress(param).await {
            tracing::debug!(error = ?error, "MCP progress notification not delivered");
        }
    }
}

/// Parses tool arguments at the boundary.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(crate) fn parse<T>(arguments: Value) -> Result<T, McpFailure>
where
    T: DeserializeOwned,
{
    serde_json::from_value(arguments).map_err(|_error| McpFailure::InvalidArguments)
}

/// The projection members a call's arguments request; none when absent or malformed.
pub(crate) fn requested_fields(arguments: &Value) -> Vec<String> {
    arguments
        .get("fields")
        .and_then(Value::as_array)
        .map_or_default(|names| {
            names
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
}

/// The JSON schema of `T` with its `op` property restricted to `ops`.
pub(crate) fn schema_with_ops<T>(ops: &[&str]) -> Arc<JsonObject>
where
    T: JsonSchema + 'static,
{
    let mut schema = (*schema_for_type::<T>()).clone();
    if let Some(Value::Object(op)) = schema
        .get_mut("properties")
        .and_then(|properties| properties.get_mut("op"))
    {
        drop(op.insert("enum".to_owned(), json!(ops)));
    }
    if let Some(Value::Object(confirm)) = schema
        .get_mut("properties")
        .and_then(|properties| properties.get_mut("confirm"))
    {
        drop(confirm.insert("description".to_owned(), json!(CONFIRM_DOC)));
    }
    Arc::new(schema)
}

/// Builds a route whose result passes through the shared shaping and error contract.
pub(crate) fn route<F>(
    description: &ToolDescription,
    schema: Arc<JsonObject>,
    call: F,
) -> ToolRoute<KccMcp>
where
    F: for<'call> Fn(&'call KccMcp, Value, Option<Progress>) -> ToolFuture<'call>
        + Send
        + Sync
        + 'static,
{
    let takes_cursor = schema
        .get("properties")
        .and_then(|properties| properties.get("cursor"))
        .is_some();
    let tool = Tool::new(description.name, description.description, schema)
        .with_annotations(description.tool_annotations());
    let name = description.name;
    let read_only = description.read_only;
    ToolRoute::new_dyn(tool, move |context: ToolCallContext<'_, KccMcp>| {
        let service = context.service;
        let arguments = Value::Object(context.arguments.unwrap_or_default());
        let progress = Progress::from_request(
            &context.request_context,
            service.privacy.redact_clients_in_mcp,
        );
        let router = ["host", "router", "source", "target"]
            .into_iter()
            .find_map(|key| arguments.get(key).and_then(Value::as_str))
            .map(str::to_owned);
        let fields = requested_fields(&arguments);
        let cursor = takes_cursor
            .then(|| parse_cursor(arguments.get("cursor").and_then(Value::as_str)).unwrap_or(0));
        let pending = call(service, arguments, progress);
        Box::pin(async move {
            Ok(finish_with_context(
                service,
                FailureContext::new(name, read_only, router.as_deref()).with_input(&fields, cursor),
                pending,
            )
            .await
            .into())
        })
    })
}
