//! The system pages against the fake router.
//!
//! What each role sees and may do, changes applied through the change workflow and read
//! back, values refused before anything is sent, router refusals in the router's own
//! words, management changes inside the fail-safe timer, and destructive ones behind the
//! typed router name.

#[path = "explorer_pages/support.rs"]
mod support;

use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};
use url::form_urlencoded::byte_serialize;

use crate::support::{Fixture, TestResult};

/// `text` as askama escapes it.
pub(crate) fn html(text: &str) -> String {
    text.replace('&', "&#38;")
        .replace('<', "&#60;")
        .replace('>', "&#62;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

/// An English message, escaped for HTML.
pub(crate) fn en(key: MessageKey) -> String {
    html(&tr(Locale::En, key, None))
}

/// `pairs` form-encoded.
pub(crate) fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                byte_serialize(name.as_bytes()).collect::<String>(),
                byte_serialize(value.as_bytes()).collect::<String>()
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// The CLI change targets the audit log recorded, in order.
///
/// # Errors
///
/// Returns the audit log's read or chain failure.
pub(crate) fn cli_targets(fixture: &Fixture) -> TestResult<Vec<String>> {
    Ok(fixture
        .audit()?
        .into_iter()
        .filter(|entry| entry.action == "router.change_cli")
        .map(|entry| entry.target.unwrap_or_default())
        .collect())
}

/// Whether the audit log has `action` ending as `outcome`.
///
/// # Errors
///
/// Returns the audit log's read or chain failure.
pub(crate) fn audited(fixture: &Fixture, action: &str, outcome: &str) -> TestResult<bool> {
    Ok(fixture
        .audit()?
        .iter()
        .any(|entry| entry.action == action && entry.outcome == outcome))
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "system_pages/users.rs"]
mod users;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "system_pages/user_changes.rs"]
mod user_changes;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "system_pages/services.rs"]
mod services;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "system_pages/general.rs"]
mod general;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "system_pages/components.rs"]
mod components;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "system_pages/storage.rs"]
mod storage;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "system_pages/schedules.rs"]
mod schedules;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "system_pages/keendns.rs"]
mod keendns;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "system_pages/diagnostics.rs"]
mod diagnostics;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "system_pages/logs.rs"]
mod logs;
