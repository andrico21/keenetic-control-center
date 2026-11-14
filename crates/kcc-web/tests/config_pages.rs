//! The configuration and backups page against the fake router (KN-1811).
//!
//! What each role sees and may do, the router scope, Save and the fail-safe timer's
//! commit and rollback, backups created, uploaded, compared, downloaded with or without
//! their secrets and deleted, and the restore actions.

#[expect(
    dead_code,
    reason = "the shared Web UI test support; this suite needs part of it"
)]
#[path = "support/mod.rs"]
mod support;

use axum::response::Response;

use crate::support::{
    outcome::TestResult,
    web::{Browser, Fixture},
};

/// The page under test.
pub(crate) const PAGE: &str = "/ui/r/home/config";

/// Multipart boundary of the test uploads.
const BOUNDARY: &str = "kcc-config-boundary";

/// Uploads `file` as `name` to the backup upload, as htmx sends it.
///
/// # Errors
///
/// Returns a failed request.
pub(crate) async fn upload(
    fixture: &Fixture,
    browser: &Browser,
    (name, file): (&str, &[u8]),
) -> TestResult<Response> {
    let mut body = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\
         Content-Type: text/plain\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(file);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    let kind = format!("multipart/form-data; boundary={BOUNDARY}");
    fixture
        .post_body(&format!("{PAGE}/backups/upload"), browser, (&kind, body))
        .await
}

/// The backup file names a page offers, newest first, from its comparison form.
pub(crate) fn backup_names(page: &str) -> Vec<String> {
    let Some((_, from)) = page.split_once("name=\"from\"") else {
        return Vec::new();
    };
    let options = from.split_once("</select>").map_or(from, |(list, _)| list);
    options
        .split("<option value=\"")
        .skip(1)
        .filter_map(|option| option.split_once('"').map(|(value, _)| value.to_owned()))
        .collect()
}

/// The lines a diff page marks as `change` (`removed` or `added`), in order.
pub(crate) fn changed(page: &str, change: &str) -> Vec<String> {
    page.split(&format!("data-change=\"{change}\""))
        .skip(1)
        .filter_map(|part| {
            let (_, code) = part.split_once("<code class=\"config-diff__code\">")?;
            code.split_once("</code>").map(|(line, _)| line.to_owned())
        })
        .collect()
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "config_pages/view.rs"]
mod view;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "config_pages/safety.rs"]
mod safety;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "config_pages/files.rs"]
mod files;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "config_pages/restore.rs"]
mod restore;
