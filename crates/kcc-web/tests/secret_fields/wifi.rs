//! The Wi-Fi password of an access point.

use core::{slice, str, time::Duration};

use axum::http::StatusCode;
use futures_util::StreamExt as _;
use kcc_i18n::keys;
use tokio::time::{Instant, timeout_at};

use crate::{
    ROUTER, TraceCapture, dummy, nowhere, setup, stored,
    support::{
        outcome::TestResult,
        page::{assert_native_post, en_with, text},
        web::{Browser, Fixture},
    },
};

/// The 5 GHz access point.
const POINT: &str = "WifiMaster1/AccessPoint0";

/// Its dialog and write, the name in the query string.
const DIALOG: &str = "/ui/r/prod-1/wifi/psk?name=WifiMaster1%2FAccessPoint0";

/// Its settings, where Edit opens the dialog.
const SETTINGS: &str = "/ui/r/prod-1/wifi/settings?name=WifiMaster1%2FAccessPoint0";

/// The stored password of the access point: `ns3 <blob>`.
fn psk(fixture: &Fixture) -> TestResult<Option<String>> {
    let config = fixture.router(ROUTER)?.running_config_text();
    Ok(stored(
        &config,
        &format!("interface {POINT}"),
        "authentication wpa-psk ",
    ))
}

/// Posts `typed` and `again` as the new password and its repetition.
async fn post(
    fixture: &Fixture,
    browser: &Browser,
    (typed, again): (&str, &str),
) -> TestResult<(StatusCode, String)> {
    let response = fixture
        .post_form(
            DIALOG,
            browser,
            &[("secret", typed), ("secret_again", again)],
        )
        .await?;
    Ok((response.status(), text(response).await?))
}

/// The router's live event stream as `browser` reads it, up to its first live region.
async fn streamed(fixture: &Fixture, browser: &Browser) -> TestResult<String> {
    let response = fixture.get("/ui/sse/r/prod-1/traffic", browser).await?;
    assert_eq!(response.status(), StatusCode::OK, "the stream opened");
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(10))
        .ok_or("deadline overflow")?;
    let mut body = response.into_body().into_data_stream();
    let mut received = String::new();
    while !received.contains("event: live") {
        let chunk = timeout_at(deadline, body.next())
            .await?
            .ok_or("the stream ended early")??;
        received.push_str(str::from_utf8(&chunk)?);
    }
    Ok(received)
}

/// What the settings say about the password, as the domain reads it: Set or Not set.
fn shown_password(settings: &str) -> Option<&str> {
    let row = settings.split_once("id=\"ap-password\"")?.1;
    let value = row.split_once("<dd class=\"settings__value\">")?.1;
    value.split_once("</dd>").map(|(shown, _)| shown)
}

#[tokio::test]
async fn a_wifi_password_reaches_the_router_and_nothing_else() -> TestResult {
    let trace = TraceCapture::install();
    let fixture = setup::fixture().await?;
    let operator = fixture.login("operator").await?;
    let mut served = Vec::new();
    let settings = text(fixture.get(SETTINGS, &operator).await?).await?;
    assert!(
        settings.contains(&format!("hx-get=\"{DIALOG}\"")),
        "Edit opens the dialog: {settings}"
    );
    let dialog = text(fixture.get(DIALOG, &operator).await?).await?;
    assert_native_post(&dialog)?;
    for shown in [
        "name=\"secret\" type=\"password\" value=\"\" autocomplete=\"new-password\"".to_owned(),
        format!(
            " minlength=\"8\" maxlength=\"63\" data-kcc-invalid=\"{}\"",
            en_with(keys::WEB_SECRET_WIFI_RULE, &[])
        ),
        "name=\"secret_again\" type=\"password\" value=\"\"".to_owned(),
    ] {
        assert!(
            dialog.contains(&shown),
            "the dialog misses {shown}: {dialog}"
        );
    }
    let before = psk(&fixture)?;
    let secret = dummy("wifi", 1);
    let (status, answer) = post(&fixture, &operator, (&secret, &secret)).await?;
    assert_eq!(status, StatusCode::OK, "written: {answer}");
    let what = en_with(keys::WEB_WIFI_PSK, &[]);
    assert!(
        answer.contains(&en_with(keys::WEB_SECRET_DONE, &[("what", &what)])),
        "the read-back's verdict: {answer}"
    );
    assert!(answer.contains("id=\"unsaved-badge\""), "unsaved: {answer}");
    let written = psk(&fixture)?.ok_or("no password stored")?;
    let blob = written.strip_prefix("ns3 ").ok_or("stored in clear")?;
    assert!(
        blob.len() >= 24,
        "a plausible encoded length: {}",
        blob.len()
    );
    assert_ne!(Some(written.clone()), before, "a new value");
    let reread = text(fixture.get(SETTINGS, &operator).await?).await?;
    assert_eq!(
        shown_password(&reread),
        Some(en_with(keys::WEB_INTERNET_SET, &[]).as_str()),
        "the domain reads a stored password: {reread}"
    );
    let page = text(fixture.get("/ui/r/prod-1/wifi", &operator).await?).await?;
    let live = streamed(&fixture, &operator).await?;
    served.extend([settings, dialog, answer, reread, page, live]);
    nowhere(&secret, &served, (&fixture, &trace))?;
    let audit = fixture.outcomes("web.wifi_psk")?;
    assert_eq!(audit, ["success"], "audited once");
    Ok(())
}

#[tokio::test]
async fn a_short_or_mistyped_wifi_password_is_refused_before_any_request() -> TestResult {
    let trace = TraceCapture::install();
    let fixture = setup::fixture().await?;
    let operator = fixture.login("operator").await?;
    drop(fixture.get(DIALOG, &operator).await?);
    let before = fixture.router(ROUTER)?.request_count();
    let short = dummy("w", 2).chars().take(7).collect::<String>();
    let (short_status, refused) = post(&fixture, &operator, (&short, &short)).await?;
    nowhere(&short, slice::from_ref(&refused), (&fixture, &trace))?;
    assert_eq!(
        short_status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "too short: {refused}"
    );
    assert!(
        refused.contains(&format!(
            "<p class=\"field__error\" id=\"secret-new-error\">{}</p>",
            en_with(keys::WEB_SECRET_WIFI_RULE, &[])
        )),
        "the rule under the field: {refused}"
    );
    assert!(refused.contains("aria-invalid=\"true\""), "marked invalid");
    let long = "x".repeat(64);
    let (long_status, too_long) = post(&fixture, &operator, (&long, &long)).await?;
    assert_eq!(long_status, StatusCode::UNPROCESSABLE_ENTITY, "too long");
    let typed = dummy("wifi", 3);
    let other = dummy("wifi", 4);
    let (differ_status, mismatch) = post(&fixture, &operator, (&typed, &other)).await?;
    assert_eq!(
        differ_status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "different entries"
    );
    assert!(
        mismatch.contains(&en_with(keys::WEB_SECRET_MISMATCH, &[])),
        "says so: {mismatch}"
    );
    assert_eq!(
        fixture.router(ROUTER)?.request_count(),
        before,
        "the router heard nothing"
    );
    for secret in [&short, &long, &typed, &other] {
        nowhere(
            secret,
            &[refused.clone(), too_long.clone(), mismatch.clone()],
            (&fixture, &trace),
        )?;
    }
    assert_eq!(
        fixture.outcomes("web.wifi_psk")?,
        ["validation_failed"; 3],
        "each refusal audited"
    );
    Ok(())
}

#[tokio::test]
async fn empty_fields_keep_the_stored_wifi_password() -> TestResult {
    let fixture = setup::fixture().await?;
    let operator = fixture.login("operator").await?;
    let secret = dummy("wifi", 5);
    let (set_status, _) = post(&fixture, &operator, (&secret, &secret)).await?;
    assert_eq!(set_status, StatusCode::OK, "set first");
    let kept = psk(&fixture)?.ok_or("no password stored")?;
    let before = fixture.router(ROUTER)?.request_count();
    let (kept_status, answer) = post(&fixture, &operator, ("", "")).await?;
    assert_eq!(kept_status, StatusCode::OK, "answered: {answer}");
    assert!(
        answer.contains(&en_with(keys::WEB_SECRET_UNCHANGED, &[])),
        "nothing sent: {answer}"
    );
    let other = dummy("wifi", 6);
    let in_query = format!("{DIALOG}&secret={other}&secret_again={other}");
    let ignored = fixture
        .post_form(
            &in_query,
            &operator,
            &[("secret", ""), ("secret_again", "")],
        )
        .await?;
    assert_eq!(
        ignored.status(),
        StatusCode::OK,
        "only the form body counts"
    );
    assert!(
        text(ignored)
            .await?
            .contains(&en_with(keys::WEB_SECRET_UNCHANGED, &[])),
        "a value in the query string is never used"
    );
    assert_eq!(
        fixture.router(ROUTER)?.request_count(),
        before,
        "no request"
    );
    assert_eq!(psk(&fixture)?, Some(kept), "the stored password stays");
    assert_eq!(
        fixture.outcomes("web.wifi_psk")?,
        ["success", "unchanged", "unchanged"],
        "audited"
    );
    Ok(())
}
