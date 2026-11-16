//! The confirmation contract of a management change made from a router page.
//!
//! The first request, sent without a confirmation, answers the kit's dialog explaining
//! the recovery timer and sends the router no command; the dialog's confirm button, which
//! sends the request again with `confirm=yes`, runs it inside the timer: armed first,
//! disarmed last.

use axum::http::StatusCode;
use kcc_i18n::keys;

use super::{
    outcome::TestResult,
    page::{form, text},
    web::{Browser, Fixture},
};

/// The commands the router received after its first `before` requests.
pub(crate) fn commands_since(fixture: &Fixture, before: usize) -> Vec<String> {
    fixture
        .handle()
        .request_log()
        .iter()
        .skip(before)
        .filter_map(|record| record.command().map(str::to_owned))
        .collect()
}

/// `POST path` of `pairs` as `browser`, without a confirmation: the kit's management
/// dialog, and no command sent. Returns where the dialog's confirm button posts.
///
/// # Panics
///
/// When the answer is not the dialog or a command reached the router.
// cancel-safe: a request answered by the dialog sends the router nothing.
pub(crate) async fn asks_first(
    fixture: &Fixture,
    browser: &Browser,
    (path, pairs): (&str, &[(&str, &str)]),
) -> TestResult<String> {
    let before = fixture.handle().request_log().len();
    let response = fixture.post(path, browser, &form(pairs)).await?;
    assert_eq!(response.status(), StatusCode::OK, "{path}");
    let body = text(response).await?;
    let marker = format!(
        "data-message-key=\"{}\"",
        keys::WEB_KIT_CONFIRM_MANAGEMENT_TEXT.id()
    );
    assert!(body.contains(&marker), "{path}: the dialog: {body}");
    assert_eq!(
        commands_since(fixture, before),
        Vec::<String>::new(),
        "{path}: nothing sent before the confirmation"
    );
    let confirm = body
        .split(" hx-post=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .ok_or("the dialog posts somewhere")?;
    Ok(confirm.replace("&#38;", "&"))
}

/// `POST path` of `pairs` and `confirm=yes` as `browser`: the change runs inside the
/// recovery timer of the router's `mode` (`router` or `extender`).
///
/// # Panics
///
/// When the change did not run, or ran outside the recovery timer.
// NOT cancel-safe: a cancelled request may have sent its change.
pub(crate) async fn runs_in_timer(
    fixture: &Fixture,
    browser: &Browser,
    (path, pairs): (&str, &[(&str, &str)]),
    mode: &str,
) -> TestResult {
    let (arm, disarm) = if mode == "router" {
        (
            "system configuration fail-safe timer reboot 300",
            "no system configuration fail-safe timer",
        )
    } else {
        ("system reboot 300", "no system reboot")
    };
    let before = fixture.handle().request_log().len();
    let confirmed: Vec<(&str, &str)> = pairs.iter().copied().chain([("confirm", "yes")]).collect();
    let response = fixture.post(path, browser, &form(&confirmed)).await?;
    assert_eq!(response.status(), StatusCode::OK, "{path} {mode}");
    let sent = commands_since(fixture, before);
    assert_eq!(
        sent.first().map(String::as_str),
        Some(arm),
        "{path} {mode}: {sent:?}"
    );
    assert_eq!(
        sent.last().map(String::as_str),
        Some(disarm),
        "{path} {mode}: {sent:?}"
    );
    assert!(sent.len() > 2, "{path} {mode}: the change itself: {sent:?}");
    Ok(())
}
