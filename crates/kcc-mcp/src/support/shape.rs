//! Result shaping: secret redaction, client pseudonyms, projection, and the byte budget.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::PoisonError;

use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::{Value, json};

use crate::{KccMcp, McpFailure};

/// Hard ceiling on any configured result budget.
const MAX_RESULT_BYTES_HARD: usize = 8 * 1024 * 1024;

/// Process-wide request correlation counter.
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Converts a tool outcome into a protocol result with a correlation id.
pub(crate) async fn finish(
    server: &KccMcp,
    tool: &'static str,
    read_only: bool,
    result: Result<Value, McpFailure>,
) -> CallToolResult {
    let request_id = format!("mcp-{}", NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed));
    match result.and_then(|value| shape(server, value, Some(&request_id))) {
        Ok(text) => CallToolResult::success(vec![ContentBlock::text(text)]),
        Err(error) => {
            tracing::warn!(request_id, code = error.code(), "MCP tool request failed");
            super::audit::failure(server, tool, read_only, &error, &request_id).await;
            let mut reply = json!({
                "error": error.code(),
                "request_id": request_id
            });
            if let (McpFailure::VerificationFailed { field }, Value::Object(object)) =
                (&error, &mut reply)
            {
                drop(object.insert("field".to_owned(), Value::String(field.clone())));
            }
            let text = serde_json::to_string(&reply)
                .unwrap_or_else(|_error| "{\"error\":\"internal\"}".to_owned());
            CallToolResult::error(vec![ContentBlock::text(text)])
        }
    }
}

/// Redacts, pseudonymizes, projects, and budgets one result value.
pub(crate) fn shape(
    server: &KccMcp,
    mut value: Value,
    request_id: Option<&str>,
) -> Result<String, McpFailure> {
    redact_secrets(&mut value);
    if server.privacy.redact_clients_in_mcp {
        let mut pseudonyms = server
            .pseudonyms
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        pseudonymize(&mut value, &mut pseudonyms, None);
    }
    let fields = value.get("fields").and_then(Value::as_array).map(|items| {
        items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>()
    });
    if let Some(selected) = fields {
        project(&mut value, &selected);
    }
    let encoded = serde_json::to_string(&value).map_err(|error| {
        tracing::error!(error = ?error, "MCP result serialization failed");
        McpFailure::Internal
    })?;
    let cap = usize::try_from(server.config.max_result_bytes)
        .unwrap_or(usize::MAX)
        .min(MAX_RESULT_BYTES_HARD);
    if encoded.len() <= cap {
        return Ok(encoded);
    }
    let truncated = json!({
        "truncated": true,
        "next_cursor": "1",
        "request_id": request_id
    });
    let fallback = serde_json::to_string(&truncated).map_err(|_error| McpFailure::Internal)?;
    if fallback.len() > cap {
        return Err(McpFailure::Internal);
    }
    Ok(fallback)
}

/// Replaces every secret-shaped key's value with a marker.
pub(crate) fn redact_secrets(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                let lowered = key.to_ascii_lowercase();
                if [
                    "password",
                    "passwd",
                    "token",
                    "secret",
                    "api_key",
                    "private_key",
                    "ns3",
                    "psk",
                    "preshared",
                ]
                .iter()
                .any(|needle| lowered.contains(needle))
                {
                    *nested = Value::String("<redacted>".to_owned());
                } else {
                    redact_secrets(nested);
                }
            }
        }
        Value::Array(values) => {
            for nested in values {
                redact_secrets(nested);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// Replaces client identifiers with stable per-session pseudonyms.
pub(crate) fn pseudonymize(
    value: &mut Value,
    pseudonyms: &mut BTreeMap<String, String>,
    parent_key: Option<&str>,
) {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                pseudonymize(nested, pseudonyms, Some(key));
            }
        }
        Value::Array(values) => {
            for nested in values {
                pseudonymize(nested, pseudonyms, parent_key);
            }
        }
        Value::String(text) if client_identifier(parent_key, text) => {
            let next = pseudonyms.len().saturating_add(1);
            let replacement = pseudonyms
                .entry(text.clone())
                .or_insert_with(|| format!("client-{next}"))
                .clone();
            *text = replacement;
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// Whether a string under `parent_key` identifies a client.
fn client_identifier(parent_key: Option<&str>, value: &str) -> bool {
    let key_match = parent_key.is_some_and(|key| {
        let lowered = key.to_ascii_lowercase();
        ["mac", "hostname", "host_name", "ip", "address"]
            .iter()
            .any(|needle| lowered.contains(needle))
    });
    key_match || looks_like_mac(value)
}

/// Whether `value` is a colon-separated MAC address.
fn looks_like_mac(value: &str) -> bool {
    value.len() == 17
        && value.split(':').count() == 6
        && value
            .split(':')
            .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// Keeps only the selected top-level fields.
fn project(value: &mut Value, fields: &[String]) {
    let Value::Object(object) = value else {
        return;
    };
    object.retain(|key, _nested| fields.contains(key));
}
