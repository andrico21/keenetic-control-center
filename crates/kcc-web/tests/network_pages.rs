//! The network pages against the fake router.
//!
//! The pages are the interfaces, the internet connections, Wi-Fi and the mesh. Each page
//! is checked per role, with one change read back with the unsaved badge, one value
//! refused before anything is sent and one router refusal shown in the router's own
//! words; the interfaces page also proves the management guard around taking `Bridge0`
//! down.

#[path = "explorer_pages/support.rs"]
mod support;

use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};
use kcc_rci::{ObjectName, RciBody, RciPath};
use serde_json::Value;
use url::form_urlencoded::byte_serialize;

use crate::support::{Fixture, ROUTER, TestResult};

/// `text` as askama escapes it.
pub(crate) fn html(text: &str) -> String {
    text.replace('&', "&#38;")
        .replace('<', "&#60;")
        .replace('>', "&#62;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

/// A message in `locale`, escaped for HTML.
pub(crate) fn said(locale: Locale, key: MessageKey) -> String {
    html(&tr(locale, key, None))
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

/// The fake router's `show interface` answer for `name`.
///
/// # Errors
///
/// Fails the test when the router does not answer with the interface.
pub(crate) async fn interface(fixture: &Fixture, name: &str) -> TestResult<Value> {
    let client = fixture.registry().client(ROUTER).await?;
    match client
        .show_interface(&ObjectName::try_from(name.to_owned())?)
        .await?
    {
        RciBody::Json(response) => response
            .value
            .pointer("/show/interface")
            .cloned()
            .ok_or_else(|| "no interface in the answer".into()),
        RciBody::Text(_) | _ => Err("the interface answer is not JSON".into()),
    }
}

/// The fake router's `show last-change` answer.
///
/// # Errors
///
/// Fails the test when the router does not answer with JSON.
pub(crate) async fn last_change(fixture: &Fixture) -> TestResult<Value> {
    let client = fixture.registry().client(ROUTER).await?;
    match client
        .show(&RciPath::from_segments(["show", "last-change"])?, &())
        .await?
    {
        RciBody::Json(response) => Ok(response.value),
        RciBody::Text(_) | _ => Err("the last-change answer is not JSON".into()),
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "network_pages/interfaces.rs"]
mod interfaces;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "network_pages/interface_guard.rs"]
mod interface_guard;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "network_pages/internet.rs"]
mod internet;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "network_pages/interface_drawer.rs"]
mod interface_drawer;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "network_pages/internet_checks.rs"]
mod internet_checks;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "network_pages/wifi.rs"]
mod wifi;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "network_pages/mesh.rs"]
mod mesh;
