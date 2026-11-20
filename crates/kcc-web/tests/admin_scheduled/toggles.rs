//! Pausing, resuming and deleting schedules, and the page without a scheduler.

use axum::http::StatusCode;
use kcc_app::schedules::model::{Action, Owner, PauseReason, ScheduleState};
use kcc_i18n::keys;

use crate::{
    changes::reboot_form,
    fixture::{PAGE, Scheduled},
    stub::Stub,
    support::{
        outcome::TestResult,
        page::{en, text},
    },
};

/// Regression (todo 15): pause, resume (re-stamping the owner to the clicker) and a
/// confirmed delete round trip, each audited.
#[tokio::test]
async fn pause_resume_and_delete_round_trip() -> TestResult {
    let fixture = Scheduled::build(Some(Stub::new())).await?;
    let schedule = fixture.stored("Nightly backup", Action::Backup)?;
    let sam = fixture.login("sam").await?;
    let id = [("id", schedule.id.as_str())];
    let paused = fixture.post("/ui/admin/scheduled/pause", &sam, &id).await?;
    assert_eq!(paused.status(), StatusCode::OK, "paused");
    let state = fixture.schedules()?.first().map(|stored| stored.state);
    assert!(
        matches!(
            state,
            Some(ScheduleState::Paused {
                reason: PauseReason::Manual,
                at: _
            })
        ),
        "paused by hand: {state:?}"
    );
    let resumed = fixture
        .post("/ui/admin/scheduled/resume", &sam, &id)
        .await?;
    assert_eq!(resumed.status(), StatusCode::OK, "resumed");
    let after = fixture.schedules()?;
    let back = after.first().ok_or("still stored")?;
    assert_eq!(back.state, ScheduleState::Active, "active again");
    assert_eq!(
        back.owner,
        Owner::Web {
            username: "sam".to_owned()
        },
        "the resumer owns it"
    );
    let delete = format!("/ui/admin/scheduled/delete?id={}", schedule.id);
    let asked = fixture.post(&delete, &sam, &[]).await?;
    assert_eq!(asked.status(), StatusCode::OK, "asks first");
    assert_eq!(fixture.schedules()?.len(), 1, "not deleted unconfirmed");
    let deleted = fixture.post(&delete, &sam, &[("confirm", "yes")]).await?;
    assert_eq!(deleted.status(), StatusCode::OK, "deleted");
    assert!(fixture.schedules()?.is_empty(), "gone");
    for action in [
        "web.schedule_pause",
        "web.schedule_resume",
        "web.schedule_delete",
    ] {
        let outcomes: Vec<String> = fixture
            .audited(action)
            .await?
            .into_iter()
            .map(|entry| entry.outcome)
            .collect();
        assert_eq!(outcomes, ["success"], "{action}");
    }
    Ok(())
}

/// Regression (todo 15): without a running scheduler the page says where schedules run,
/// offers no add, edit, resume or run-now, and refuses a new schedule as unavailable.
#[tokio::test]
async fn without_a_scheduler_the_page_refuses_new_schedules() -> TestResult {
    let fixture = Scheduled::build(None).await?;
    drop(fixture.stored("Nightly backup", Action::Backup)?);
    let admin = fixture.login("admin").await?;
    let page = fixture.html(PAGE, &admin).await?;
    assert!(
        page.contains(&en(keys::WEB_ADMIN_SCHEDULED_NOT_RUNNING)),
        "the notice"
    );
    for absent in [
        "hx-get=\"/ui/admin/scheduled/new\"",
        "/ui/admin/scheduled/edit?",
        "/ui/admin/scheduled/run-now?",
    ] {
        assert!(!page.contains(absent), "no {absent}");
    }
    assert!(page.contains("/ui/admin/scheduled/pause"), "pause stays");
    let refused = fixture.post(PAGE, &admin, &reboot_form("home")).await?;
    assert_eq!(
        refused.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "refused"
    );
    assert!(
        text(refused)
            .await?
            .contains(&en(keys::WEB_SCHEDULED_REFUSED_UNAVAILABLE)),
        "unavailable"
    );
    assert_eq!(fixture.schedules()?.len(), 1, "nothing added");
    Ok(())
}
