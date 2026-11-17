//! Reading what the Web UI answered: bodies, headers, cookies and messages as the pages
//! render them.

use axum::{body::to_bytes, response::Response};
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};
use url::form_urlencoded::byte_serialize;

use super::outcome::TestResult;

/// Largest response body a test reads.
const BODY_CAP: usize = 0x0100_0000;

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
    said(Locale::En, key)
}

/// An English message with `args`, escaped for HTML.
pub(crate) fn en_with(key: MessageKey, args: &[(&str, &str)]) -> String {
    let mut fluent = FluentArgs::new();
    for (name, value) in args {
        fluent.set(*name, (*value).to_owned());
    }
    html(&tr(Locale::En, key, Some(&fluent)))
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

/// The response body as text.
pub(crate) async fn text(response: Response) -> TestResult<String> {
    let bytes = to_bytes(response.into_body(), BODY_CAP).await?;
    Ok(String::from_utf8(bytes.to_vec())?)
}

/// A header of `response` as text.
pub(crate) fn header_text(response: &Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// The `name=value` pair of the response's `Set-Cookie`.
pub(crate) fn cookie_pair(response: &Response) -> TestResult<String> {
    header_text(response, "set-cookie")
        .and_then(|value| value.split(';').next().map(str::to_owned))
        .ok_or_else(|| "missing Set-Cookie".into())
}

/// The content of the `<meta name="{name}">` tag of a rendered page.
pub(crate) fn meta_content(html: &str, name: &str) -> Option<String> {
    let marker = format!("<meta name=\"{name}\" content=\"");
    html.split_once(&marker)
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(value, _)| value.to_owned())
}

/// The "router said" list of an outcome.
pub(crate) fn router_said(body: &str) -> Option<String> {
    body.split_once("<ul class=\"router-said__list\">")
        .and_then(|(_, tail)| tail.split_once("</ul>"))
        .map(|(list, _)| list.to_owned())
}

/// Checks that the form holding a password input posts natively to the same target as
/// htmx.
pub(crate) fn assert_native_post(html: &str) -> TestResult {
    let password = html.find("type=\"password\"").ok_or("no password input")?;
    let before = html.get(..password).ok_or("password position")?;
    let start = before.rfind("<form").ok_or("no form around password")?;
    let tag = html
        .get(start..)
        .and_then(|tail| tail.split_once('>').map(|(tag, _)| tag))
        .ok_or("incomplete form tag")?;
    let attribute = |name: &str| {
        let (_, tail) = tag.split_once(&format!(" {name}=\""))?;
        tail.split_once('"').map(|(value, _)| value)
    };
    if attribute("method") != Some("post") {
        return Err(format!("unsafe native method: {tag}").into());
    }
    let action = attribute("action").ok_or("secret form has no native action")?;
    if action.is_empty() {
        return Err(format!("secret form action is empty: {tag}").into());
    }
    if Some(action) != attribute("hx-post") {
        return Err(format!("native and htmx targets differ: {tag}").into());
    }
    Ok(())
}

/// The text of `html` without its tags.
fn inner_text(html: &str) -> String {
    let mut text = String::new();
    let mut in_tag = false;
    for character in html.chars() {
        match character {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => text.push(character),
            _ => {}
        }
    }
    text.trim().to_owned()
}

/// The elements of `html` whose opening tag starts with `open` (such as `<dd`), as their
/// opening tags and inner text, in order; `close` ends each (such as `</dd>`).
fn elements(html: &str, (open, close): (&str, &str)) -> Vec<(String, String)> {
    html.split(open)
        .skip(1)
        .filter_map(|rest| {
            let (tag, after) = rest.split_once('>')?;
            let (inner, _) = after.split_once(close)?;
            Some((tag.to_owned(), inner_text(inner)))
        })
        .collect()
}

/// The number of the wizard step the step list marks current (`aria-current="step"`).
pub(crate) fn current_step(html: &str) -> Option<u32> {
    let (_, text) = elements(html, ("<li class=\"wizard-steps__item\"", "</li>"))
        .into_iter()
        .find(|(tag, _)| tag.contains("aria-current=\"step\""))?;
    text.split_whitespace().next()?.parse().ok()
}

/// The `(term, value)` pairs of the description lists of `html`, as text without tags.
pub(crate) fn facts(html: &str) -> Vec<(String, String)> {
    let terms = elements(html, ("<dt", "</dt>"));
    let values = elements(html, ("<dd", "</dd>"));
    terms
        .into_iter()
        .zip(values)
        .map(|((_, term), (_, value))| (term, value))
        .collect()
}

/// The tone of every notice of `html` (`<div class="notice" data-tone="...">`).
pub(crate) fn notice_tones(html: &str) -> Vec<String> {
    elements(html, ("<div class=\"notice\"", "</div>"))
        .into_iter()
        .filter_map(|(tag, _)| {
            tag.split_once("data-tone=\"")
                .and_then(|(_, tail)| tail.split_once('"'))
                .map(|(tone, _)| tone.to_owned())
        })
        .collect()
}

/// The text of every row header (`<th scope="row" ...>`) of `html`'s tables.
pub(crate) fn row_headers(html: &str) -> Vec<String> {
    elements(html, ("<th scope=\"row\"", "</th>"))
        .into_iter()
        .map(|(_, text)| text)
        .collect()
}
