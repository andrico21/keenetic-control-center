//! Result shaping: secret redaction, client pseudonyms, projection, and the byte budget.

use alloc::collections::BTreeMap;
use std::sync::PoisonError;

use kcc_app::audit::receipt::AuditReceipt;
use kcc_config::mask::mask_json;
use serde_json::Value;

use super::truncate::Shaping;
use crate::{KccMcp, McpFailure, support::validate::valid_host};

/// Non-secret context retained from parsed tool input for failure auditing.
#[derive(Clone, Copy)]
pub(crate) struct FailureContext<'call> {
    tool: &'static str,
    read_only: bool,
    router: Option<&'call str>,
    fields: &'call [String],
    cursor: Option<usize>,
}

impl<'call> FailureContext<'call> {
    /// Describes one tool call before its result is known.
    pub(crate) fn new(tool: &'static str, read_only: bool, router: Option<&'call str>) -> Self {
        Self {
            tool,
            read_only,
            router: router.filter(|value| valid_host(value).is_ok()),
            fields: &[],
            cursor: None,
        }
    }

    /// The same call, projecting its list items to `fields` and paging from `cursor`.
    pub(crate) const fn with_input(self, fields: &'call [String], cursor: Option<usize>) -> Self {
        Self {
            fields,
            cursor,
            ..self
        }
    }

    /// How this call's result is shaped, answering `request_id`.
    pub(super) const fn shaping(&self, request_id: Option<&'call str>) -> Shaping<'call> {
        Shaping::new(request_id).with_input(self.fields, self.cursor)
    }

    /// Tool registry name used as the audit action suffix.
    pub(super) const fn tool(&self) -> &'static str {
        self.tool
    }

    /// Whether router and internal failures are non-changing reads.
    pub(super) const fn read_only(&self) -> bool {
        self.read_only
    }

    /// Router id retained from the parsed input, when present.
    pub(super) const fn router(&self) -> Option<&str> {
        self.router
    }
}

/// Hard ceiling on any configured result budget.
const MAX_RESULT_BYTES_HARD: usize = 8 * 1024 * 1024;

/// `result` with `"audit_pending": true` while the change's audit entry is still queued
/// behind another process's append lock; it is written once the lock is free.
pub(crate) fn noting(mut result: Value, audit: &AuditReceipt) -> Value {
    if audit.is_pending()
        && let Value::Object(object) = &mut result
    {
        drop(object.insert("audit_pending".to_owned(), Value::Bool(true)));
    }
    result
}

/// Redacts, pseudonymizes, projects, and budgets one result value.
pub(crate) fn shape(
    server: &KccMcp,
    mut value: Value,
    shaping: Shaping<'_>,
) -> Result<String, McpFailure> {
    mask_json(&mut value, "<redacted>");
    if server.privacy.redact_clients_in_mcp {
        let mut pseudonyms = server
            .pseudonyms
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        pseudonymize(&mut value, &mut pseudonyms, None);
    }
    shaping.project(&mut value);
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
    shaping.cut(&value, cap)
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

#[cfg(test)]
#[expect(clippy::missing_panics_doc, reason = "test code fails by panicking")]
mod tests {
    use super::FailureContext;

    /// Failure audit context must discard malformed router identifiers.
    #[test]
    fn failure_context_retains_only_valid_router_identifiers() {
        let oversized = "a".repeat(300);
        for (router, expected) in [
            (oversized.as_str(), None),
            ("../etc", None),
            ("Bad Host", None),
            ("lab-1", Some("lab-1")),
        ] {
            let context = FailureContext::new("kcc_rci_execute", false, Some(router));
            assert_eq!(context.router(), expected);
        }
    }
}
