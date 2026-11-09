//! Dynamic RMCP routes for registry-generated tools and their progress reporting.

use alloc::sync::Arc;
use core::pin::Pin;

use rmcp::{
    handler::server::{common::schema_for_type, router::tool::ToolRoute, tool::ToolCallContext},
    model::{JsonObject, ProgressNotificationParam, ProgressToken, Tool, ToolAnnotations},
    service::{Peer, RequestContext, RoleServer},
};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::shape::{FailureContext, finish_with_context};
use crate::{KccMcp, McpFailure, registry::definitions::ToolDescription};

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
}

impl Progress {
    /// Captures the request's progress token, when present.
    pub(crate) fn from_request(context: &RequestContext<RoleServer>) -> Option<Self> {
        context.meta.get_progress_token().map(|token| Self {
            peer: context.peer.clone(),
            token,
        })
    }

    /// Sends one notification; a closed session only loses the notification.
    pub(crate) async fn notify(&self, progress: u32, message: String) {
        let param = ProgressNotificationParam::new(self.token.clone(), f64::from(progress))
            .with_message(message);
        if let Err(error) = self.peer.notify_progress(param).await {
            tracing::debug!(error = ?error, "MCP progress notification not delivered");
        }
    }
}

/// Parses tool arguments at the boundary.
pub(crate) fn parse<T>(arguments: Value) -> Result<T, McpFailure>
where
    T: DeserializeOwned,
{
    serde_json::from_value(arguments).map_err(|_error| McpFailure::InvalidArguments)
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
    let annotations = ToolAnnotations::new()
        .read_only(description.read_only)
        .destructive(description.destructive)
        .idempotent(description.idempotent)
        .open_world(false);
    let tool =
        Tool::new(description.name, description.description, schema).with_annotations(annotations);
    let name = description.name;
    let read_only = description.read_only;
    ToolRoute::new_dyn(tool, move |context: ToolCallContext<'_, KccMcp>| {
        let service = context.service;
        let arguments = Value::Object(context.arguments.unwrap_or_default());
        let progress = Progress::from_request(&context.request_context);
        let router = ["host", "router", "source", "target"]
            .into_iter()
            .find_map(|key| arguments.get(key).and_then(Value::as_str))
            .map(str::to_owned);
        let pending = call(service, arguments, progress);
        Box::pin(async move {
            Ok(finish_with_context(
                service,
                FailureContext::new(name, read_only, router.as_deref()),
                pending.await,
            )
            .await
            .into())
        })
    })
}
