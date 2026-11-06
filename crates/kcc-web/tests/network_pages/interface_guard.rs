//! The management guard of the interfaces page.
//!
//! Taking `Bridge0` down asks first with the fail-safe explanation, runs inside the
//! router's fail-safe timer and leaves the change unsaved; a router refusal under the
//! guard still disarms the timer.

use axum::http::StatusCode;
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::FaultInjection;
use serde_json::Value;

use crate::{
    html, interface, last_change, said,
    support::{Fixture, ROUTER, TestResult, header_text, text},
};

/// Disabling `Bridge0`.
const DOWN: &str = "/ui/r/home/network/state?name=Bridge0&state=down";

/// The catalog path of the fail-safe timer's arm and disarm lines.
const TIMER: &str = "system configuration fail-safe timer";

/// The targets of the change workflow's CLI entries, in order.
fn cli_targets(fixture: &Fixture) -> TestResult<Vec<String>> {
    Ok(fixture
        .audit()?
        .into_iter()
        .filter(|entry| entry.action == "router.change_cli")
        .map(|entry| entry.target.unwrap_or_default())
        .collect())
}

#[tokio::test]
async fn bridge0_down_asks_then_runs_inside_the_fail_safe_timer() -> TestResult {
    let fixture = Fixture::new().await?;
    let startup = fixture.handle().startup_config_text();
    let operator = fixture.login("operator").await?;
    let denied = fixture.post(DOWN, &operator, "").await?;
    assert_eq!(
        denied.status(),
        StatusCode::FORBIDDEN,
        "a management change needs Destructive"
    );
    let admin = fixture.login("admin").await?;
    drop(fixture.get("/ui/r/home/network", &admin).await?);
    let before = fixture.handle().request_count();
    let asked = fixture.post(DOWN, &admin, "").await?;
    assert_eq!(
        header_text(&asked, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "the dialog"
    );
    let prompt = text(asked).await?;
    let mut args = FluentArgs::new();
    args.set("router", ROUTER);
    args.set("minutes", "5");
    let explanation = html(&tr(
        Locale::En,
        keys::WEB_KIT_CONFIRM_MANAGEMENT_TEXT,
        Some(&args),
    ));
    assert!(
        prompt.contains(&said(Locale::En, keys::WEB_KIT_CONFIRM_MANAGEMENT_TITLE)),
        "management title: {prompt}"
    );
    assert!(prompt.contains(&explanation), "the fail-safe timer");
    assert!(
        prompt.contains(
            "hx-post=\"/ui/r/home/network/state?name=Bridge0&#38;state=down\" hx-target=\"#page-outcome\""
        ),
        "confirming sends the change again"
    );
    assert!(!prompt.contains("confirm_name"), "no name to type");
    assert_eq!(
        fixture.handle().request_count(),
        before,
        "nothing reaches the router before the confirmation"
    );
    let confirmed = fixture.post(DOWN, &admin, "confirm=yes").await?;
    assert_eq!(confirmed.status(), StatusCode::OK, "applied");
    let body = text(confirmed).await?;
    for expected in [
        said(Locale::En, keys::WEB_KIT_DONE_UNSAVED),
        "id=\"unsaved-badge\" hx-swap-oob=\"true\"".to_owned(),
        "id=\"net-region\" hx-swap-oob=\"true\"".to_owned(),
    ] {
        assert!(body.contains(&expected), "missing {expected} in {body}");
    }
    assert_eq!(
        cli_targets(&fixture)?,
        [TIMER, "interface up", TIMER],
        "armed, changed, disarmed"
    );
    let state = last_change(&fixture).await?;
    assert_eq!(
        state.pointer("/fail-safe/active"),
        Some(&Value::Bool(false)),
        "disarmed: {state}"
    );
    assert_eq!(
        state.get("unsaved"),
        Some(&Value::Bool(true)),
        "still unsaved"
    );
    assert_eq!(
        fixture.handle().startup_config_text(),
        startup,
        "nothing saved"
    );
    let bridge = interface(&fixture, "Bridge0").await?;
    assert_eq!(
        bridge.get("state").and_then(Value::as_str),
        Some("down"),
        "read back down"
    );
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.interface_down" && entry.outcome == "success"),
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn a_refusal_under_the_guard_still_disarms_the_timer() -> TestResult {
    let fixture =
        Fixture::with_faults(FaultInjection::default().refuse_management_bridge_down(true)).await?;
    let admin = fixture.login("admin").await?;
    let response = fixture.post(DOWN, &admin, "confirm=yes").await?;
    assert_eq!(response.status(), StatusCode::OK, "answered");
    let body = text(response).await?;
    assert!(
        body.contains(&said(Locale::En, keys::WEB_KIT_REJECTED)),
        "localized: {body}"
    );
    assert!(
        body.contains("<li>management bridge cannot be disabled.</li>"),
        "the router's words"
    );
    assert!(!body.contains("unsaved-badge"), "no badge for a refusal");
    assert_eq!(
        cli_targets(&fixture)?,
        [TIMER, TIMER],
        "armed and disarmed around the refused change"
    );
    let state = last_change(&fixture).await?;
    assert_eq!(
        state.pointer("/fail-safe/active"),
        Some(&Value::Bool(false)),
        "disarmed: {state}"
    );
    let bridge = interface(&fixture, "Bridge0").await?;
    assert_eq!(
        bridge.get("state").and_then(Value::as_str),
        Some("up"),
        "still up"
    );
    Ok(())
}
