//! Save and the fail-safe timer: what the page reports, Keep changes, and Roll back behind
//! the typed router name.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    PAGE, audited, en, form, get, post, sign_in,
    support::{Fixture, ROUTER, TestResult, text},
};

/// Changes the fake router's running configuration and arms its fail-safe timer.
async fn change_and_arm(fixture: &Fixture, description: &str) -> TestResult {
    let client = fixture.registry().client(ROUTER).await?;
    drop(
        client
            .parse(&format!("interface Bridge0 description {description}"))
            .await?,
    );
    drop(
        client
            .parse("system configuration fail-safe timer reboot 300")
            .await?,
    );
    Ok(())
}

#[tokio::test]
async fn save_writes_the_running_configuration() -> TestResult {
    let fixture = Fixture::new().await?;
    let client = fixture.registry().client(ROUTER).await?;
    drop(
        client
            .parse("interface Bridge0 description unsaved-change")
            .await?,
    );
    let viewer = sign_in(&fixture, "viewer").await?;
    let shown = text(get(&fixture, &viewer, PAGE).await?).await?;
    assert!(
        shown.contains(&en(keys::WEB_ROUTER_UNSAVED)),
        "unsaved: {shown}"
    );
    assert!(!shown.contains("/config/save\""), "a viewer has no Save");
    let operator = sign_in(&fixture, "operator").await?;
    let page = text(get(&fixture, &operator, PAGE).await?).await?;
    assert!(
        page.contains("hx-post=\"/ui/r/home/config/save\""),
        "Save while unsaved: {page}"
    );
    let saved = post(&fixture, &operator, (&format!("{PAGE}/save"), "")).await?;
    assert_eq!(saved.status(), StatusCode::OK, "saved");
    let answer = text(saved).await?;
    assert!(answer.contains(&en(keys::WEB_KIT_DONE)), "toast: {answer}");
    assert!(
        answer.contains("id=\"config-status\" hx-swap-oob=\"true\"")
            && answer.contains(&en(keys::WEB_CONFIG_SAVED)),
        "the state read back: {answer}"
    );
    assert!(
        fixture
            .handle()
            .startup_config_text()
            .contains("unsaved-change"),
        "persisted"
    );
    assert!(audited(&fixture, "web.config_save", "success")?, "audited");
    Ok(())
}

#[tokio::test]
async fn keep_changes_commits_only_while_the_timer_runs() -> TestResult {
    let fixture = Fixture::new().await?;
    change_and_arm(&fixture, "guarded-change").await?;
    let operator = sign_in(&fixture, "operator").await?;
    let page = text(get(&fixture, &operator, PAGE).await?).await?;
    for shown in [en(keys::WEB_CONFIG_ARMED), en(keys::WEB_CONFIG_COMMIT)] {
        assert!(page.contains(&shown), "armed page misses {shown}: {page}");
    }
    assert!(
        !page.contains("/config/rollback\""),
        "an operator cannot roll back"
    );
    assert!(
        !page.contains("/config/save\""),
        "Keep changes, not Save, while the timer runs"
    );
    let kept = post(&fixture, &operator, (&format!("{PAGE}/commit"), "")).await?;
    assert_eq!(kept.status(), StatusCode::OK, "committed");
    let answer = text(kept).await?;
    assert!(
        answer.contains(&en(keys::WEB_CONFIG_NOT_ARMED_LABEL)),
        "disarmed and read back: {answer}"
    );
    assert!(
        fixture
            .handle()
            .startup_config_text()
            .contains("guarded-change"),
        "saved"
    );
    let again = text(post(&fixture, &operator, (&format!("{PAGE}/commit"), "")).await?).await?;
    assert!(
        again.contains(&en(keys::WEB_CONFIG_NOT_ARMED)),
        "nothing to commit: {again}"
    );
    assert!(audited(&fixture, "web.config_commit", "success")?, "kept");
    assert!(
        audited(&fixture, "web.config_commit", "not_armed")?,
        "refused"
    );
    Ok(())
}

#[tokio::test]
async fn roll_back_needs_the_router_name_and_restores_the_saved_configuration() -> TestResult {
    let fixture = Fixture::new().await?;
    change_and_arm(&fixture, "rolled-change").await?;
    let rollback = format!("{PAGE}/rollback");
    let operator = sign_in(&fixture, "operator").await?;
    let denied = post(&fixture, &operator, (&rollback, "")).await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN, "operator");
    let admin = sign_in(&fixture, "admin").await?;
    let asked = text(post(&fixture, &admin, (&rollback, "")).await?).await?;
    assert!(
        asked.contains("hx-post=\"/ui/r/home/config/rollback\"")
            && asked.contains("name=\"confirm_name\""),
        "asks for the router name: {asked}"
    );
    let mistyped = form(&[("confirm", "yes"), ("confirm_name", "Home")]);
    let refused = text(post(&fixture, &admin, (&rollback, &mistyped)).await?).await?;
    assert!(
        refused.contains("field__error"),
        "the name must match: {refused}"
    );
    assert!(
        fixture
            .handle()
            .running_config_text()
            .contains("rolled-change"),
        "nothing rolled back yet"
    );
    let named = form(&[("confirm", "yes"), ("confirm_name", "home")]);
    let done = text(post(&fixture, &admin, (&rollback, &named)).await?).await?;
    assert!(
        done.contains(&en(keys::WEB_KIT_DONE_TERMINAL)),
        "carried out: {done}"
    );
    assert!(
        !fixture
            .handle()
            .running_config_text()
            .contains("rolled-change"),
        "the saved configuration is back"
    );
    assert!(
        audited(&fixture, "web.config_rollback", "success")?,
        "audited"
    );
    Ok(())
}
