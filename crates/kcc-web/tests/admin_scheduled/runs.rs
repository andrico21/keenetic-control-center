//! Running a schedule now through the scheduler, and the last run the table shows.

extern crate alloc;

use alloc::sync::Arc;

use axum::http::StatusCode;
use kcc_app::schedules::{
    ledger::{RunLedger, RunOutcome, Trigger},
    model::Action,
};
use kcc_i18n::keys;
use kcc_web::admin_scheduled::ScheduleRefusal;

use crate::{
    changes::reboot_form,
    fixture::{PAGE, Scheduled},
    stub::{Asked, Stub},
    support::{
        outcome::TestResult,
        page::{en, en_with, html, text},
    },
};

/// Regression (todo 15): a confirmed run-now asks the scheduler once, as the clicker, and
/// the table shows the run's result once the ledger has it.
#[tokio::test]
async fn run_now_asks_the_scheduler_once_as_the_clicker() -> TestResult {
    let stub = Stub::new();
    let fixture = Scheduled::build(Some(Arc::clone(&stub))).await?;
    let schedule = fixture.stored("Nightly backup", Action::Backup)?;
    let sam = fixture.login("sam").await?;
    let run = format!("/ui/admin/scheduled/run-now?id={}", schedule.id);
    let dialog = fixture.html(&run, &sam).await?;
    assert!(
        dialog.contains("name=\"confirm\" value=\"yes\""),
        "asks first"
    );
    let unconfirmed = fixture.post(&run, &sam, &[]).await?;
    assert_eq!(unconfirmed.status(), StatusCode::OK, "asks again");
    assert!(stub.asked().is_empty(), "nothing ran unconfirmed");
    let started = fixture.post(&run, &sam, &[("confirm", "yes")]).await?;
    assert_eq!(started.status(), StatusCode::OK, "admitted");
    assert!(
        text(started)
            .await?
            .contains(&en(keys::WEB_ADMIN_SCHEDULED_RUN_ADMITTED)),
        "the run started"
    );
    assert_eq!(
        stub.asked(),
        vec![Asked::Run(
            "scheduler".to_owned(),
            "web:sam".to_owned(),
            schedule.id.clone()
        )],
        "one run as sam"
    );
    let ledger = RunLedger::new(fixture.store().clone());
    let requested_by = "web:sam".to_owned();
    let began = ledger.begin(&schedule.id, Trigger::Now { requested_by }, 1_700_000_100)?;
    let done = RunOutcome::Succeeded {
        unsaved: false,
        checksum: None,
    };
    ledger.finish(&schedule.id, began, done, None, 1_700_000_160)?;
    let page = fixture.html(PAGE, &sam).await?;
    assert!(
        page.contains(&en(keys::WEB_ADMIN_SCHEDULED_RUN_SUCCEEDED)),
        "the last run's result"
    );
    let outcomes: Vec<String> = fixture
        .audited("web.schedule_run_now")
        .await?
        .into_iter()
        .map(|entry| entry.outcome)
        .collect();
    assert_eq!(outcomes, ["success"], "audited");
    Ok(())
}

/// Regression (todo 15): a run-now the scheduler refuses as busy shows the busy message
/// and is audited as refused; the page does not retry it.
#[tokio::test]
async fn a_busy_router_refuses_run_now() -> TestResult {
    let stub = Stub::new();
    stub.refuse_runs(ScheduleRefusal::Busy);
    let fixture = Scheduled::build(Some(Arc::clone(&stub))).await?;
    let schedule = fixture.stored("Nightly backup", Action::Backup)?;
    let admin = fixture.login("admin").await?;
    let run = format!("/ui/admin/scheduled/run-now?id={}", schedule.id);
    let refused = fixture.post(&run, &admin, &[("confirm", "yes")]).await?;
    assert_eq!(
        refused.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "refused"
    );
    assert!(
        text(refused)
            .await?
            .contains(&en(keys::WEB_SCHEDULED_REFUSED_BUSY)),
        "the busy message"
    );
    assert_eq!(stub.asked().len(), 1, "asked once, no retry");
    let outcomes: Vec<String> = fixture
        .audited("web.schedule_run_now")
        .await?
        .into_iter()
        .map(|entry| entry.outcome)
        .collect();
    assert_eq!(outcomes, ["busy"], "audited as busy");
    Ok(())
}

/// Regression (todo 15): running a restart now needs the router's name typed.
#[tokio::test]
async fn running_a_reboot_now_needs_the_typed_router_name() -> TestResult {
    let stub = Stub::new();
    let fixture = Scheduled::build(Some(Arc::clone(&stub))).await?;
    let schedule = fixture.stored("Weekly restart", Action::Reboot)?;
    let admin = fixture.login("admin").await?;
    let run = format!("/ui/admin/scheduled/run-now?id={}", schedule.id);
    let mistyped = fixture
        .post(
            &run,
            &admin,
            &[("confirm", "yes"), ("confirm_name", "other")],
        )
        .await?;
    assert!(
        text(mistyped)
            .await?
            .contains(&en(keys::WEB_ADMIN_SCHEDULED_ERROR_CONFIRM)),
        "the mismatch"
    );
    assert!(stub.asked().is_empty(), "nothing ran");
    let started = fixture
        .post(
            &run,
            &admin,
            &[("confirm", "yes"), ("confirm_name", "home")],
        )
        .await?;
    assert_eq!(started.status(), StatusCode::OK, "admitted");
    assert_eq!(stub.asked().len(), 1, "ran once");
    Ok(())
}

/// Todo 11: a labelled router is named by its name in the table, and a restart asks for
/// its id: in the run-now dialog and under the editor's typed field.
#[tokio::test]
async fn a_labelled_router_is_named_and_a_restart_asks_for_its_id() -> TestResult {
    let name = "Home Office";
    let fixture = Scheduled::build(Some(Stub::new())).await?;
    fixture.web().label("home", name).await?;
    let schedule = fixture.stored("Weekly restart", Action::Reboot)?;
    let admin = fixture.login("admin").await?;
    let page = fixture.html(PAGE, &admin).await?;
    assert!(
        page.contains(&format!(">{}</td>", html(name))),
        "the table names the router: {page}"
    );
    for key in [
        keys::WEB_ADMIN_SCHEDULED_RUN_REBOOT_TEXT,
        keys::WEB_ADMIN_SCHEDULED_REBOOT_HELP,
    ] {
        assert_ne!(
            en_with(key, &[("id", "home")]),
            en_with(key, &[("id", "other")]),
            "{key:?} names the id to type"
        );
    }
    let run = format!("/ui/admin/scheduled/run-now?id={}", schedule.id);
    let dialog = fixture.html(&run, &admin).await?;
    let asked = en_with(keys::WEB_ADMIN_SCHEDULED_RUN_REBOOT_TEXT, &[("id", "home")]);
    assert!(dialog.contains(&asked), "the run-now dialog: {dialog}");
    let refused = fixture.post(PAGE, &admin, &reboot_form(name)).await?;
    assert_eq!(
        refused.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "the name is not the id"
    );
    let help = en_with(keys::WEB_ADMIN_SCHEDULED_REBOOT_HELP, &[("id", "home")]);
    let editor = text(refused).await?;
    assert!(editor.contains(&help), "the editor's field: {editor}");
    Ok(())
}
