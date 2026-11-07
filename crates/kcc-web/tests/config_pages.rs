//! The configuration and backups page against the fake router (KN-1811).
//!
//! What each role sees and may do, the router scope, Save and the fail-safe timer's
//! commit and rollback, backups created, uploaded, compared, downloaded with or without
//! their secrets and deleted, and the restore actions.

#[expect(
    dead_code,
    reason = "the shared explorer fixture; this suite needs only part of it"
)]
#[path = "explorer_pages/support.rs"]
mod support;

use axum::{
    body::Body,
    http::{Method, Request, header, request::Builder},
    response::Response,
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};
use url::form_urlencoded::byte_serialize;

use crate::support::{Fixture, TestResult, header_text, text};

/// The only browser origin the fixture accepts.
const ORIGIN: &str = "http://127.0.0.1:8080";

/// Password of every fixture account.
const PASSWORD: &str = "correct horse battery staple";

/// The page under test.
pub(crate) const PAGE: &str = "/ui/r/home/config";

/// Multipart boundary of the test uploads.
const BOUNDARY: &str = "kcc-config-boundary";

/// A signed-in browser: its session cookie and CSRF token.
pub(crate) struct Signed {
    /// `kcc_session=<id>`.
    cookie: String,
    /// Token for `X-CSRF-Token`.
    csrf: String,
}

/// The `name=value` pair of the response's `Set-Cookie`.
///
/// # Errors
///
/// Returns an error when the response sets no cookie.
fn cookie(response: &Response) -> TestResult<String> {
    header_text(response, "set-cookie")
        .and_then(|value| value.split(';').next().map(str::to_owned))
        .ok_or_else(|| "missing Set-Cookie".into())
}

/// The CSRF token of a rendered page.
///
/// # Errors
///
/// Returns an error when the page carries no token.
fn meta(page: &str) -> TestResult<String> {
    page.split_once("<meta name=\"csrf-token\" content=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(token, _)| token.to_owned())
        .ok_or_else(|| "no CSRF token".into())
}

/// Signs `username` in.
///
/// # Errors
///
/// Returns a failed request or a missing cookie or token.
pub(crate) async fn sign_in(fixture: &Fixture, username: &str) -> TestResult<Signed> {
    let page = fixture
        .send(Request::get("/ui/login").body(Body::empty())?)
        .await?;
    let anonymous = cookie(&page)?;
    let token = meta(&text(page).await?)?;
    let login = same_origin(Method::POST, "/ui/login", (&anonymous, &token))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "username={username}&password={}",
            PASSWORD.replace(' ', "+")
        )))?;
    let session = cookie(&fixture.send(login).await?)?;
    let account = fixture
        .send(
            Request::get("/ui/account")
                .header(header::COOKIE, &session)
                .body(Body::empty())?,
        )
        .await?;
    Ok(Signed {
        cookie: session,
        csrf: meta(&text(account).await?)?,
    })
}

/// A same-origin request builder carrying `cookie` and `csrf`, as htmx sends it.
fn same_origin(method: Method, path: &str, (cookie, csrf): (&str, &str)) -> Builder {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, ORIGIN)
        .header("sec-fetch-site", "same-origin")
        .header("hx-request", "true")
        .header("x-csrf-token", csrf)
}

/// `GET path` as `signed`.
///
/// # Errors
///
/// Returns a failed request.
pub(crate) async fn get(fixture: &Fixture, signed: &Signed, path: &str) -> TestResult<Response> {
    fixture
        .send(
            Request::get(path)
                .header(header::COOKIE, &signed.cookie)
                .body(Body::empty())?,
        )
        .await
}

/// A form `POST` of `body` to `path` as `signed`.
///
/// # Errors
///
/// Returns a failed request.
pub(crate) async fn post(
    fixture: &Fixture,
    signed: &Signed,
    (path, body): (&str, &str),
) -> TestResult<Response> {
    let request = same_origin(Method::POST, path, (&signed.cookie, &signed.csrf))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_owned()))?;
    fixture.send(request).await
}

/// Uploads `file` as `name` to the backup upload, as htmx sends it.
///
/// # Errors
///
/// Returns a failed request.
pub(crate) async fn upload(
    fixture: &Fixture,
    signed: &Signed,
    (name, file): (&str, &[u8]),
) -> TestResult<Response> {
    let mut body = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\
         Content-Type: text/plain\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(file);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    let request = same_origin(
        Method::POST,
        &format!("{PAGE}/backups/upload"),
        (&signed.cookie, &signed.csrf),
    )
    .header(
        header::CONTENT_TYPE,
        format!("multipart/form-data; boundary={BOUNDARY}"),
    )
    .header(header::CONTENT_LENGTH, body.len())
    .body(Body::from(body))?;
    fixture.send(request).await
}

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
