//! Execution from the explorer: reads, changes through the change workflow, validation
//! failures and router refusals.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    en, form,
    support::{Fixture, TestResult, header_text, text},
};

/// A read runs through the shared client without the change workflow; a long answer
/// is shown in pages, later ones collapsed.
#[tokio::test]
async fn reads_bypass_the_workflow_and_large_answers_are_paged() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("viewer").await?;
    let response = fixture
        .post(
            "/ui/r/home/explorer/execute",
            &browser,
            &form(&[("path", "show ip nat")]),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "read");
    let body = text(response).await?;
    assert!(
        body.contains(&en(keys::WEB_EXPLORER_DONE)),
        "completed: {body}"
    );
    assert!(
        body.contains("<details class=\"viewer__page\">"),
        "later pages collapsed"
    );
    assert!(
        !body.contains("hx-swap-oob=\"true\""),
        "a read leaves no unsaved badge"
    );
    assert!(
        !body.contains("explorer/response"),
        "480 NAT rows fit under the render cap, so nothing is kept for download"
    );
    let nothing = fixture
        .get("/ui/r/home/explorer/response", &browser)
        .await?;
    assert_eq!(nothing.status(), StatusCode::NOT_FOUND, "no kept response");
    let audit = fixture.audit()?;
    assert!(
        audit
            .iter()
            .any(|entry| entry.action == "web.explorer_execute" && entry.outcome == "success"),
        "audited"
    );
    assert!(
        !audit
            .iter()
            .any(|entry| entry.action.starts_with("router.change")),
        "no change set"
    );
    assert_eq!(fixture.backups()?, 0, "no backup for a read");
    Ok(())
}

/// A change asks first, then runs through the change workflow: a backup, the router's
/// answer, the unsaved badge and an audit trail without values.
#[tokio::test]
async fn changes_confirm_then_back_up_apply_and_audit() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    let mac = "02:00:00:00:00:99";
    let fields = [
        ("path", "ip hotspot host"),
        ("a.mac", mac),
        ("a.permit", "true"),
    ];
    let asked = fixture
        .post("/ui/r/home/explorer/execute", &browser, &form(&fields))
        .await?;
    assert_eq!(
        header_text(&asked, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "dialog"
    );
    assert!(
        text(asked)
            .await?
            .contains(&en(keys::WEB_EXPLORER_CONFIRM_WRITE_TITLE)),
        "asks"
    );
    assert!(
        !fixture
            .handle()
            .settings_snapshot()
            .to_string()
            .contains(mac),
        "nothing applied yet"
    );
    let mut confirmed = fields.to_vec();
    confirmed.push(("confirm", "yes"));
    let applied = fixture
        .post("/ui/r/home/explorer/execute", &browser, &form(&confirmed))
        .await?;
    assert_eq!(applied.status(), StatusCode::OK, "applied");
    assert_eq!(
        header_text(&applied, "hx-trigger").as_deref(),
        Some("kcc:dialog-close"),
        "closes"
    );
    let body = text(applied).await?;
    assert!(
        body.contains(&en(keys::WEB_EXPLORER_DONE_UNSAVED)),
        "done: {body}"
    );
    assert!(
        body.contains("id=\"unsaved-badge\" hx-swap-oob=\"true\""),
        "badge update"
    );
    assert!(body.contains("hx-swap-oob=\"beforeend:#toasts\""), "toast");
    assert!(
        fixture
            .handle()
            .settings_snapshot()
            .to_string()
            .contains(mac),
        "router changed"
    );
    assert_eq!(fixture.backups()?, 1, "one pre-change backup");
    let audit = fixture.audit()?;
    assert!(
        audit
            .iter()
            .any(|entry| entry.action == "router.change_batch"
                && entry.target.as_deref() == Some("ip hotspot host")),
        "change workflow audit"
    );
    let web = audit
        .iter()
        .find(|entry| entry.action == "web.explorer_execute" && entry.outcome == "success")
        .ok_or("no web audit")?;
    assert!(
        !web.params_redacted.to_string().contains(mac),
        "field names only"
    );
    Ok(())
}

/// An invalid value is reported with its field and nothing reaches the router.
#[tokio::test]
async fn invalid_values_are_reported_and_nothing_is_sent() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    drop(fixture.get("/ui/r/home/explorer", &browser).await?);
    let before = fixture.handle().request_count();
    let response = fixture
        .post(
            "/ui/r/home/explorer/execute",
            &browser,
            &form(&[
                ("path", "ip hotspot host"),
                ("a.mac", "not-a-mac"),
                ("confirm", "yes"),
            ]),
        )
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "not sent"
    );
    let body = text(response).await?;
    assert!(body.contains("mac: invalid value."), "field named: {body}");
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    Ok(())
}

/// A router refusal shows the localized error and the router's own words.
#[tokio::test]
async fn router_refusals_show_what_the_router_said() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    let response = fixture
        .post(
            "/ui/r/home/explorer/execute",
            &browser,
            &form(&[
                ("path", "ip hotspot host"),
                ("a.mac", "02:00:00:00:00:98"),
                ("a.no", "true"),
                ("confirm", "yes"),
                ("confirm_name", "home"),
            ]),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "answered");
    let body = text(response).await?;
    assert!(
        body.contains(&en(keys::WEB_EXPLORER_REJECTED)),
        "localized error: {body}"
    );
    assert!(
        body.contains(&en(keys::WEB_EXPLORER_ROUTER_SAID)),
        "router said block"
    );
    assert!(
        body.contains("<li>Item 1: not found.</li>"),
        "the router's message"
    );
    Ok(())
}
