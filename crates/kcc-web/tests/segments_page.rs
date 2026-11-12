//! The segments list and its delete: a segment created with the wizard is listed with what
//! it has, deleted after its router's name is typed, and the router is back where it
//! started; a viewer sees no delete and is refused, a wrong name or a segment that changed
//! after the dialog opened deletes nothing, and a partial segment is listed and deletable.

#[expect(
    dead_code,
    reason = "the shared explorer fixture; this suite needs only part of it"
)]
#[path = "explorer_pages/support.rs"]
mod support;

use axum::http::StatusCode;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};
use url::form_urlencoded::byte_serialize;

use crate::support::{Browser, Fixture, TestResult, text};

/// The page under test.
pub(crate) const PAGE: &str = "/ui/r/home/segments";

/// A segment beside the fixture's home network, with one trunk port and a Wi-Fi network.
pub(crate) const SEGMENT: [(&str, &str); 9] = [
    ("id", "23"),
    ("vlan", "23"),
    ("address", "198.51.100.1"),
    ("mask", "255.255.255.0"),
    ("begin", "198.51.100.10"),
    ("end", "198.51.100.50"),
    ("port", "GigabitEthernet0/1"),
    ("access_point", "WifiMaster0/AccessPoint1"),
    ("policy", ""),
];

/// `text` as askama escapes it.
pub(crate) fn html(text: &str) -> String {
    text.replace('&', "&#38;")
        .replace('<', "&#60;")
        .replace('>', "&#62;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

/// A message in English, escaped for HTML.
pub(crate) fn said(key: MessageKey) -> String {
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

/// The panel of segment `id` in `html`, from its `<section` to its `</section>`.
pub(crate) fn segment<'page>(html: &'page str, id: &str) -> Option<&'page str> {
    let at = html.find(&format!("aria-labelledby=\"segment-{id}\""))?;
    let start = html.get(..at)?.rfind("<section")?;
    let end = at.checked_add(html.get(at..)?.find("</section>")?)?;
    html.get(start..end)
}

/// Where the delete dialog's form posts, unescaped.
pub(crate) fn dialog_action(dialog: &str) -> Option<String> {
    dialog
        .split_once("hx-post=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(action, _)| action.replace("&#38;", "&"))
}

/// The parser lines the fake router received so far.
pub(crate) fn sent_lines(fixture: &Fixture) -> usize {
    fixture
        .handle()
        .request_log()
        .iter()
        .filter(|record| record.command().is_some())
        .count()
}

/// Creates `pairs` with the wizard as `browser`.
///
/// # Errors
///
/// Fails when the wizard does not answer 200.
pub(crate) async fn create(
    fixture: &Fixture,
    browser: &Browser,
    pairs: &[(&str, &str)],
) -> TestResult<String> {
    let confirmed = pairs
        .iter()
        .copied()
        .chain([("confirm", "yes"), ("confirm_name", "home")])
        .collect::<Vec<_>>();
    let created = fixture
        .post(&format!("{PAGE}/create"), browser, &form(&confirmed))
        .await?;
    if created.status() != StatusCode::OK {
        return Err(format!("the wizard answered {}", created.status()).into());
    }
    text(created).await
}

/// Opens the delete dialog of segment `id` as `browser`: its markup and its action.
///
/// # Errors
///
/// Fails when the dialog does not answer 200 or has no action.
pub(crate) async fn delete_dialog(
    fixture: &Fixture,
    browser: &Browser,
    id: &str,
) -> TestResult<(String, String)> {
    let response = fixture
        .get(&format!("{PAGE}/delete?id={id}"), browser)
        .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("the delete dialog answered {}", response.status()).into());
    }
    let dialog = text(response).await?;
    let action = dialog_action(&dialog).ok_or("the dialog has no action")?;
    Ok((dialog, action))
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "segments_page/delete.rs"]
mod delete;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "segments_page/refusals.rs"]
mod refusals;
