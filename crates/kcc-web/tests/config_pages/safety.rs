//! Save and the fail-safe timer: what the page reports, Keep changes, and Roll back behind
//! the typed router name.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    PAGE,
    support::{
        outcome::TestResult,
        page::{en, text},
        web::{Fixture, ROUTER},
    },
};

/// Changes the fake router's running configuration and arms its fail-safe timer.
pub(crate) async fn change_and_arm(fixture: &Fixture, description: &str) -> TestResult {
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
    let viewer = fixture.login("viewer").await?;
    let shown = text(fixture.get(PAGE, &viewer).await?).await?;
    assert!(
        shown.contains(&en(keys::WEB_ROUTER_UNSAVED)),
        "unsaved: {shown}"
    );
    assert!(!shown.contains("/config/save\""), "a viewer has no Save");
    let operator = fixture.login("operator").await?;
    let page = text(fixture.get(PAGE, &operator).await?).await?;
    assert!(
        page.contains("hx-post=\"/ui/r/home/config/save\""),
        "Save while unsaved: {page}"
    );
    let saved = fixture.post(&format!("{PAGE}/save"), &operator, "").await?;
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
    assert!(fixture.audited("web.config_save", "success")?, "audited");
    Ok(())
}

#[tokio::test]
async fn keep_changes_commits_only_while_the_timer_runs() -> TestResult {
    let fixture = Fixture::new().await?;
    change_and_arm(&fixture, "guarded-change").await?;
    let operator = fixture.login("operator").await?;
    let page = text(fixture.get(PAGE, &operator).await?).await?;
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
    let kept = fixture
        .post(&format!("{PAGE}/commit"), &operator, "")
        .await?;
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
    let again = text(
        fixture
            .post(&format!("{PAGE}/commit"), &operator, "")
            .await?,
    )
    .await?;
    assert!(
        again.contains(&en(keys::WEB_CONFIG_NOT_ARMED)),
        "nothing to commit: {again}"
    );
    assert!(fixture.audited("web.config_commit", "success")?, "kept");
    assert!(
        fixture.audited("web.config_commit", "not_armed")?,
        "refused"
    );
    Ok(())
}
