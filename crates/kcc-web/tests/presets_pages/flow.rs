//! Driving the presets pages as a browser does, for the tests.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support is not rendered API documentation; every error fails the test"
)]

use core::time::Duration;

use axum::{http::StatusCode, response::Response};
use kcc_rci::{RciBody, RciPath};
use serde_json::Value;
use tokio::time::timeout;

use crate::support::{
    outcome::TestResult,
    page::{header_text, text},
    web::{Browser, Fixture},
};

/// The longest a test waits for an apply's stream to close.
const STREAM_BOUND: Duration = Duration::from_secs(120);

/// The secure-DNS settings the source router gets.
pub(crate) const DNS_LINES: [&str; 2] = [
    "dns-proxy tls upstream 1.1.1.1 853",
    "dns-proxy tls upstream 9.9.9.9 853",
];

/// Sends `lines` to router `id` and saves its configuration.
pub(crate) async fn seed(fixture: &Fixture, id: &str, lines: &[&str]) -> TestResult {
    let client = fixture.registry().client(id).await?;
    for line in lines.iter().copied().chain(["system configuration save"]) {
        drop(client.parse(line).await?);
    }
    Ok(())
}

/// The `show last-change` answer of router `id`.
pub(crate) async fn last_change(fixture: &Fixture, id: &str) -> TestResult<Value> {
    let client = fixture.registry().client(id).await?;
    let path = RciPath::from_segments(["show", "last-change"])?;
    match client.get(&path, &()).await? {
        RciBody::Json(response) => Ok(response.value),
        RciBody::Text(_) | _ => Err("show last-change is not JSON".into()),
    }
}

/// The page an htmx answer sends the browser to.
pub(crate) fn redirected(response: &Response) -> TestResult<String> {
    header_text(response, "hx-redirect")
        .ok_or_else(|| format!("no redirect, status {}", response.status()).into())
}

/// Fails unless `response` sends the browser to `page`.
pub(crate) fn moved(response: &Response, page: &str) -> TestResult {
    let target = redirected(response)?;
    if target == page {
        Ok(())
    } else {
        Err(format!("moved to {target}, not {page}").into())
    }
}

/// Captures a preset named `name` of `groups` from router `router` as `browser` through
/// the new preset pages, and returns its id.
pub(crate) async fn capture(
    fixture: &Fixture,
    browser: &Browser,
    router: &str,
    (groups, name): (&[&str], &str),
) -> TestResult<String> {
    let read = fixture
        .post_multipart(
            "/ui/presets/new",
            browser,
            (&[("kind", "router"), ("router", router)], None),
        )
        .await?;
    let draft = redirected(&read)?;
    let mut pairs = groups
        .iter()
        .map(|group| ("group", *group))
        .collect::<Vec<_>>();
    pairs.push(("name", name));
    let saved = fixture.post_form(&draft, browser, &pairs).await?;
    let page = redirected(&saved)?;
    page.strip_prefix("/ui/presets/")
        .map(str::to_owned)
        .ok_or_else(|| format!("not a preset page: {page}").into())
}

/// Starts applying preset `id` as `browser` and returns the run's page.
pub(crate) async fn start(fixture: &Fixture, browser: &Browser, id: &str) -> TestResult<String> {
    let started = fixture
        .post_form(&format!("/ui/presets/{id}/apply"), browser, &[])
        .await?;
    redirected(&started)
}

/// Steps 2 to 5 of the run at `page`: target `target`, the reconciling `mode`, every
/// setting kept and `passwords` typed; ends at the preview.
pub(crate) async fn to_preview(
    fixture: &Fixture,
    browser: &Browser,
    page: &str,
    (target, mode, passwords): (&str, &str, &[(&str, &str)]),
) -> TestResult {
    for (path, pairs) in [
        ("target", vec![("router", target)]),
        ("target/continue", Vec::new()),
        ("options", vec![("mode", mode), ("regenerate", "yes")]),
        ("review/continue", Vec::new()),
        ("inputs", passwords.to_vec()),
    ] {
        let response = fixture
            .post_form(&format!("{page}/{path}"), browser, &pairs)
            .await?;
        if response.status() != StatusCode::OK {
            let status = response.status();
            return Err(format!("{path}: {status} {}", text(response).await?).into());
        }
        moved(&response, page)?;
    }
    Ok(())
}

/// Confirms the apply of `page` and returns its whole live stream, read until it closes.
pub(crate) async fn apply(fixture: &Fixture, browser: &Browser, page: &str) -> TestResult<String> {
    moved(
        &fixture
            .post_form(&format!("{page}/apply"), browser, &[("confirm", "yes")])
            .await?,
        page,
    )?;
    let response = fixture.get(&format!("{page}/events"), browser).await?;
    if response.status() != StatusCode::OK {
        return Err(format!("the stream answered {}", response.status()).into());
    }
    timeout(STREAM_BOUND, text(response)).await?
}

/// Opens the results of `page` and finishes it with `way` (`keep`, `save`, `rollback`),
/// posting `pairs`.
pub(crate) async fn finish(
    fixture: &Fixture,
    browser: &Browser,
    page: &str,
    (way, pairs): (&str, &[(&str, &str)]),
) -> TestResult {
    moved(
        &fixture
            .post_form(&format!("{page}/results"), browser, &[])
            .await?,
        page,
    )?;
    moved(
        &fixture
            .post_form(&format!("{page}/{way}"), browser, pairs)
            .await?,
        page,
    )
}
