//! Result shaping: secret redaction, client pseudonyms, projection, and the byte budget.

use kcc_app::audit::receipt::AuditReceipt;
use kcc_config::mask::mask_json;
use serde_json::Value;

use super::{scrub::pseudonymize, truncate::Shaping};
use crate::{KccMcp, McpFailure, support::validate::valid_host};

/// Non-secret context retained from parsed tool input for failure auditing.
#[derive(Clone, Copy)]
pub(crate) struct FailureContext<'call> {
    /// The protocol tool name.
    tool: &'static str,
    /// Whether the tool never changes router state.
    read_only: bool,
    /// The router the call named, when it named one.
    router: Option<&'call str>,
    /// The projection members the call requested.
    fields: &'call [String],
    /// The pagination offset the call requested.
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
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(crate) fn shape(
    server: &KccMcp,
    mut value: Value,
    shaping: Shaping<'_>,
) -> Result<String, McpFailure> {
    mask_json(&mut value, "<redacted>");
    if server.privacy.redact_clients_in_mcp {
        pseudonymize(&mut value);
    }
    shaping.project(&mut value);
    let encoded = serde_json::to_string(&value).map_err(|error| {
        tracing::error!(error = ?error, "MCP result serialization failed");
        McpFailure::Internal
    })?;
    let cap = usize::try_from(server.call_gates().max_result_bytes())
        .unwrap_or(usize::MAX)
        .min(MAX_RESULT_BYTES_HARD);
    if encoded.len() <= cap {
        return Ok(encoded);
    }
    shaping.cut(&value, cap)
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
