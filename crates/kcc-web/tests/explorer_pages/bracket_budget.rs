//! A management bracket outlives the Web request budget when its receipts wait.
//!
//! Its audit receipts wait on another process's append lock longer than the budget, and
//! the bracket still closes: the router is disarmed and the user gets the outcome instead
//! of a bare 408 (F2/F4 round 17 N75).

use core::time::Duration;

use axum::http::StatusCode;
use kcc_app::{audit::AUDIT_FILE_NAME, persist::StateStore};
use kcc_i18n::keys;
use kcc_testkit::{FakeRouter, migration, model::Profile};
use serde_json::json;
use tokio::{task::JoinHandle, time::sleep};

use crate::{
    en, form,
    support::{Fixture, TestResult, text},
};

/// The CLI console's management change: `Bridge0` removed.
const MANAGEMENT: &[(&str, &str)] = &[
    ("line", "no interface Bridge0"),
    ("confirm", "yes"),
    ("confirm_name", "home"),
];

/// The fixture over a fake router in `mode`.
// NOT cancel-safe: setup creates router and application tasks.
async fn fixture(mode: &str) -> TestResult<Fixture> {
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some(mode.to_owned());
    Fixture::with_router(
        FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario),
    )
    .await
}

/// Holds the audit append lock, as a contending `kcc` process would, for `held`.
fn hold_audit_lock(fixture: &Fixture, held: Duration) -> TestResult<JoinHandle<()>> {
    let lock = StateStore::open(&fixture.state_dir())?.try_lock(AUDIT_FILE_NAME)?;
    Ok(tokio::spawn(async move {
        sleep(held).await;
        drop(lock);
    }))
}

/// The arm and disarm lines of `mode` and whether the router received both, in order.
fn armed_then_disarmed(fixture: &Fixture, mode: &str) -> bool {
    let (arm, disarm) = if mode == "router" {
        (
            "system configuration fail-safe timer reboot 300",
            "no system configuration fail-safe timer",
        )
    } else {
        ("system reboot 300", "no system reboot")
    };
    let commands: Vec<String> = fixture
        .handle()
        .request_log()
        .iter()
        .filter_map(|record| record.command().map(str::to_owned))
        .collect();
    commands
        .iter()
        .position(|command| command == arm)
        .is_some_and(|at| commands.iter().skip(at).any(|command| command == disarm))
}

/// Both receipts of the bracket time out on the held lock, past the request budget.
///
/// They take about 26 s each against the 30 s budget; the disarm still reaches the
/// router, the answer is the armed outcome of an arm whose change was never sent and,
/// once the lock is free, the Web audit entry records `fail_safe_armed`.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test(start_paused = true)]
async fn a_held_audit_lock_does_not_cut_the_management_bracket() -> TestResult {
    for mode in ["router", "extender"] {
        let fixture = fixture(mode).await?;
        let browser = fixture.login("admin").await?;
        let held = hold_audit_lock(&fixture, Duration::from_secs(60))?;

        let response = fixture
            .post("/ui/r/home/console/cli/send", &browser, &form(MANAGEMENT))
            .await?;
        held.await?;

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{mode}: not the budget's 408"
        );
        let body = text(response).await?;
        assert!(
            body.contains(&en(keys::MANAGEMENT_NOT_SENT_ARMED)),
            "{mode}: {body}"
        );
        assert!(armed_then_disarmed(&fixture, mode), "{mode}: disarm sent");
        assert!(
            !fixture.handle().recovery_armed(),
            "{mode}: router disarmed"
        );
        let entries = fixture.audit()?;
        let web = entries
            .iter()
            .find(|entry| entry.action == "web.console_cli")
            .ok_or("missing web audit")?;
        assert_eq!(
            web.params_redacted.get("fail_safe_armed"),
            Some(&json!(true)),
            "{mode}: {web:?}"
        );
    }
    Ok(())
}

/// F4's `n75c` shape: an ordinary write and a management change while the lock is held.
///
/// The single writer queues the arm receipt behind the ordinary receipt, and the
/// management bracket still closes with an answer.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test(start_paused = true)]
async fn a_queued_arm_receipt_does_not_cut_the_management_bracket() -> TestResult {
    for mode in ["router", "extender"] {
        let fixture = fixture(mode).await?;
        let browser = fixture.login("admin").await?;
        let held = hold_audit_lock(&fixture, Duration::from_secs(100))?;

        let ordinary = form(&[("line", "system country DE")]);
        let change = form(MANAGEMENT);
        let (_ordinary, answered) = tokio::join!(
            fixture.post("/ui/r/home/console/cli/send", &browser, &ordinary),
            fixture.post("/ui/r/home/console/cli/send", &browser, &change),
        );
        held.await?;

        let management = answered?;
        assert_eq!(
            management.status(),
            StatusCode::OK,
            "{mode}: not the budget's 408"
        );
        let body = text(management).await?;
        assert!(
            body.contains(&en(keys::MANAGEMENT_NOT_SENT_ARMED)),
            "{mode}: {body}"
        );
        assert!(armed_then_disarmed(&fixture, mode), "{mode}: disarm sent");
        assert!(
            !fixture.handle().recovery_armed(),
            "{mode}: router disarmed"
        );
    }
    Ok(())
}
