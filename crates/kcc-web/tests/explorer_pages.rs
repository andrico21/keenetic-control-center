//! Command explorer, RCI console and CLI console tests against the fake router: per-role
//! controls, catalog facts and the generated form, previews, reads, changes through the
//! change workflow, validation failures that send nothing, router refusals, confirmations,
//! the fail-safe guard, background jobs and the R-MCP2 incident payload.

#[path = "explorer_pages/support.rs"]
mod support;

use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};
use url::form_urlencoded::byte_serialize;

/// The R-MCP2 incident payload: a positional array where RCI needs an object.
pub(crate) const INCIDENT: &str = r#"{"ip":{"route":["10.0.5.0","255.255.255.255","Wireguard2"]}}"#;

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

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "explorer_pages/browse.rs"]
mod browse;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "explorer_pages/execute.rs"]
mod execute;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "explorer_pages/consoles.rs"]
mod consoles;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "explorer_pages/guards.rs"]
mod guards;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "explorer_pages/persists.rs"]
mod persists;

#[cfg(test)]
#[path = "explorer_pages/nested_risk.rs"]
mod nested_risk;
