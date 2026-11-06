//! The clients, DHCP and segments pages against the fake router: what each role sees, a
//! change applied and read back, a value refused before anything is sent, and a router
//! refusal shown in the router's own words.

#[path = "explorer_pages/support.rs"]
mod support;

use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};
use url::form_urlencoded::byte_serialize;

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

/// The table row of `html` that holds `needle`, from its `<tr>` to its `</tr>`.
pub(crate) fn row<'page>(html: &'page str, needle: &str) -> Option<&'page str> {
    let at = html.find(needle)?;
    let start = html.get(..at)?.rfind("<tr>")?;
    let end = at.checked_add(html.get(at..)?.find("</tr>")?)?;
    html.get(start..end)
}

/// The "router said" list of an outcome.
pub(crate) fn router_said(body: &str) -> Option<String> {
    body.split_once("<ul class=\"router-said__list\">")
        .and_then(|(_, tail)| tail.split_once("</ul>"))
        .map(|(list, _)| list.to_owned())
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "clients_pages/clients.rs"]
mod clients;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "clients_pages/dhcp.rs"]
mod dhcp;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "clients_pages/segments.rs"]
mod segments;
