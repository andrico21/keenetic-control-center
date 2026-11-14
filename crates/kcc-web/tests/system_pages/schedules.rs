//! Schedules.
//!
//! Per-role controls, a schedule and a timed action added through the change workflow,
//! and values the router's CLI cannot take refused before anything is sent.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::support::{
    outcome::TestResult,
    page::{en, form, header_text, text},
    web::Fixture,
};

/// The page under test.
const PAGE: &str = "/ui/r/home/system/schedules";

#[tokio::test]
async fn each_role_sees_the_schedules_and_only_its_controls() -> TestResult {
    let fixture = Fixture::new().await?;
    let add = "hx-get=\"/ui/r/home/system/schedules/new\"";
    let action = "hx-get=\"/ui/r/home/system/schedules/action?name=Schedule0\"";
    for (account, changes) in [("viewer", false), ("operator", true), ("admin", true)] {
        let browser = fixture.login(account).await?;
        let page = text(fixture.get(PAGE, &browser).await?).await?;
        for shown in [
            ">Schedule0<".to_owned(),
            "Fixture schedule".to_owned(),
            en(keys::WEB_SYSTEM_SCHEDULES_ACTIVE),
        ] {
            assert!(page.contains(&shown), "{account} misses {shown}");
        }
        assert_eq!(page.contains(add), changes, "{account} add");
        assert_eq!(page.contains(action), changes, "{account} action");
    }
    let viewer = fixture.login("viewer").await?;
    let denied = fixture
        .post(PAGE, &viewer, &form(&[("name", "night")]))
        .await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN, "the route checks");
    Ok(())
}

#[tokio::test]
async fn a_schedule_and_an_action_are_added() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let created = text(
        fixture
            .post(
                PAGE,
                &operator,
                &form(&[("name", "night"), ("description", "quiet")]),
            )
            .await?,
    )
    .await?;
    assert!(created.contains("data-tone=\"success\""), "{created}");
    assert!(
        fixture
            .handle()
            .running_config_text()
            .contains("schedule night"),
        "the router has it"
    );
    let dialog = text(
        fixture
            .get(&format!("{PAGE}/action?name=Schedule0"), &operator)
            .await?,
    )
    .await?;
    assert!(dialog.contains("name=\"day\" value=\"mon\""), "{dialog}");
    let acted = text(
        fixture
            .post(
                &format!("{PAGE}/action"),
                &operator,
                &form(&[
                    ("name", "Schedule0"),
                    ("action", "start"),
                    ("time", "08:30"),
                    ("day", "mon"),
                    ("day", "fri"),
                ]),
            )
            .await?,
    )
    .await?;
    assert!(acted.contains("data-tone=\"success\""), "{acted}");
    assert!(
        fixture
            .handle()
            .running_config_text()
            .contains("action start 30 8 17"),
        "Monday and Friday at 08:30: {}",
        fixture.handle().running_config_text()
    );
    assert!(
        fixture.audited("web.schedule_create", "success")?
            && fixture.audited("web.schedule_action", "success")?,
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn values_the_router_cannot_take_are_refused_before_anything_is_sent() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    drop(fixture.get(PAGE, &operator).await?);
    let before = fixture.handle().running_config_text();
    let refused = fixture
        .post(PAGE, &operator, &form(&[("name", "night shift")]))
        .await?;
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY, "422");
    assert_eq!(
        header_text(&refused, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "back into the dialog"
    );
    assert!(
        text(refused)
            .await?
            .contains(&en(keys::WEB_SYSTEM_SCHEDULES_WORD_ERROR)),
        "one word"
    );
    let no_day = text(
        fixture
            .post(
                &format!("{PAGE}/action"),
                &operator,
                &form(&[("name", "Schedule0"), ("time", "25:00")]),
            )
            .await?,
    )
    .await?;
    for expected in [
        en(keys::WEB_SYSTEM_SCHEDULES_TIME_ERROR),
        en(keys::WEB_SYSTEM_SCHEDULES_DAYS_ERROR),
    ] {
        assert!(no_day.contains(&expected), "missing {expected}");
    }
    assert_eq!(
        fixture.handle().running_config_text(),
        before,
        "nothing changed"
    );
    assert!(
        fixture.audited("web.schedule_create", "validation_failed")?,
        "audited"
    );
    Ok(())
}
