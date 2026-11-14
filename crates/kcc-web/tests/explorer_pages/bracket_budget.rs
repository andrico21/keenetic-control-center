//! A held audit append lock neither cuts nor holds back a Web change.
//!
//! Another process holds the audit append lock: the change still reaches the router, a
//! management bracket disarms without waiting for its receipts, the user is answered
//! within a bounded time, and every entry is written, in order, once the lock is free.

use core::time::Duration;

use axum::http::StatusCode;
use kcc_app::{
    audit::{AUDIT_FILE_NAME, AuditEntry},
    persist::{StateLock, StateStore},
};
use kcc_i18n::keys;
use kcc_testkit::FaultInjection;
use tokio::{
    task::JoinHandle,
    time::{Instant, sleep},
};

use super::{commands, edges, fixture};
use crate::{
    en, form,
    support::{Browser, Fixture, TestResult, text},
};

/// The CLI console's management change: `Bridge0` removed.
const MANAGEMENT: &[(&str, &str)] = &[
    ("line", "no interface Bridge0"),
    ("confirm", "yes"),
    ("confirm_name", "home"),
];

/// Holds the audit append lock, as a contending `kcc` process would, for `held`.
fn hold_audit_lock(fixture: &Fixture, held: Duration) -> TestResult<JoinHandle<()>> {
    let lock = StateStore::open(&fixture.state_dir())?.try_lock(AUDIT_FILE_NAME)?;
    Ok(tokio::spawn(async move {
        sleep(held).await;
        drop(lock);
    }))
}

/// Whether the router received the arm and then the disarm of `mode`.
fn armed_then_disarmed(fixture: &Fixture, mode: &str) -> bool {
    let [arm, disarm] = edges(mode);
    let sent = commands(fixture);
    sent.iter()
        .position(|command| command == arm)
        .is_some_and(|at| sent.iter().skip(at).any(|command| command == disarm))
}

/// The lock holder's audit entries are not written before this limit: the bracket's wait
/// for its receipts after the disarm, plus slack for the outcome record.
const BRACKET_ANSWER: Duration = Duration::from_secs(22);

/// Takes the audit append lock, as a contending `kcc` process would, until dropped.
fn take_audit_lock(fixture: &Fixture) -> TestResult<StateLock> {
    Ok(StateStore::open(&fixture.state_dir())?.try_lock(AUDIT_FILE_NAME)?)
}

/// An ordinary console write, as `browser`.
const ORDINARY: &[(&str, &str)] = &[("line", "system country DE"), ("confirm", "yes")];

/// The audit log once the entries queued so far are written: an ordinary write sent now
/// waits for its own entry, which is queued behind them.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
async fn written_after(fixture: &Fixture, browser: &Browser) -> TestResult<Vec<AuditEntry>> {
    let later = fixture
        .post("/ui/r/home/console/cli/send", browser, &form(ORDINARY))
        .await?;
    let body = text(later).await?;
    assert!(
        !body.contains(&en(keys::AUDIT_ENTRY_PENDING)),
        "the later write's entry is written: {body}"
    );
    fixture.audit()
}

/// The actions of `entries` after sign-in, in chain order.
fn actions_after_login(entries: &[AuditEntry]) -> Vec<&str> {
    entries
        .iter()
        .map(|entry| entry.action.as_str())
        .filter(|action| *action != "web.login")
        .collect()
}

/// With the lock held, the bracket disarms before any of its receipts is written and
/// answers within its receipt wait; once the lock is free every entry is written, in
/// order, and the chain verifies.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test(start_paused = true)]
async fn a_held_audit_lock_does_not_hold_back_the_management_bracket() -> TestResult {
    for mode in ["router", "extender"] {
        let fixture = fixture(mode, FaultInjection::default()).await?;
        let browser = fixture.login("admin").await?;
        let lock = take_audit_lock(&fixture)?;

        let started = Instant::now();
        let response = fixture
            .post("/ui/r/home/console/cli/send", &browser, &form(MANAGEMENT))
            .await?;
        let waited = started.elapsed();

        assert!(
            waited <= BRACKET_ANSWER,
            "{mode}: answered after {waited:?}"
        );
        assert_eq!(response.status(), StatusCode::OK, "{mode}");
        let body = text(response).await?;
        assert!(body.contains(r#"data-tone="success""#), "{mode}: {body}");
        assert!(
            body.contains(&en(keys::AUDIT_ENTRY_PENDING)),
            "{mode}: {body}"
        );
        assert!(armed_then_disarmed(&fixture, mode), "{mode}: disarm sent");
        assert!(
            !fixture.handle().recovery_armed(),
            "{mode}: router disarmed"
        );
        assert!(
            actions_after_login(&fixture.audit()?).is_empty(),
            "{mode}: no receipt written while the lock is held"
        );

        drop(lock);
        let entries = written_after(&fixture, &browser).await?;
        assert_eq!(
            actions_after_login(&entries),
            [
                "router.change_cli",
                "router.change_cli",
                "router.change_cli",
                "web.console_cli",
                "router.change_cli",
                "web.console_cli"
            ],
            "{mode}: arm, change, disarm and the page's entry, in order, then the later write"
        );
        let web = entries
            .iter()
            .find(|entry| entry.action == "web.console_cli")
            .ok_or("missing web audit")?;
        assert_eq!(web.outcome, "success", "{mode}: {web:?}");
    }
    Ok(())
}

/// An ordinary write under a held lock is reported as applied, not as a failure, and
/// its entries are written once the lock is free.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test(start_paused = true)]
async fn an_ordinary_write_under_a_held_lock_is_reported_applied() -> TestResult {
    let fixture = fixture("router", FaultInjection::default()).await?;
    let browser = fixture.login("admin").await?;
    let lock = take_audit_lock(&fixture)?;

    let response = fixture
        .post("/ui/r/home/console/cli/send", &browser, &form(ORDINARY))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = text(response).await?;
    assert!(body.contains(r#"data-tone="success""#), "{body}");
    assert!(body.contains(&en(keys::AUDIT_ENTRY_PENDING)), "{body}");
    drop(lock);
    let entries = written_after(&fixture, &browser).await?;
    assert_eq!(
        actions_after_login(&entries),
        [
            "router.change_cli",
            "web.console_cli",
            "router.change_cli",
            "web.console_cli"
        ]
    );
    Ok(())
}

/// A sign-in under a held lock succeeds within its wait, and its entry is written once
/// the lock is free.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test(start_paused = true)]
async fn a_login_under_a_held_lock_succeeds_and_is_audited_later() -> TestResult {
    let fixture = fixture("router", FaultInjection::default()).await?;
    let lock = take_audit_lock(&fixture)?;

    let started = Instant::now();
    let browser = fixture.login("admin").await?;
    let waited = started.elapsed();

    assert!(
        waited <= Duration::from_secs(6),
        "signed in after {waited:?}"
    );
    drop(lock);
    let actions: Vec<String> = written_after(&fixture, &browser)
        .await?
        .into_iter()
        .map(|entry| entry.action)
        .collect();
    assert_eq!(
        actions,
        ["web.login", "router.change_cli", "web.console_cli"],
        "the sign-in entry is written after the release, before the later write's"
    );
    Ok(())
}

/// F4's `n75c` shape: an ordinary write and a management change while the lock is held.
///
/// The single writer queues the arm receipt behind the ordinary receipt; the management
/// bracket still disarms and is answered as applied, with its entries pending.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test(start_paused = true)]
async fn a_queued_arm_receipt_does_not_cut_the_management_bracket() -> TestResult {
    for mode in ["router", "extender"] {
        let fixture = fixture(mode, FaultInjection::default()).await?;
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
        assert!(body.contains(r#"data-tone="success""#), "{mode}: {body}");
        assert!(
            body.contains(&en(keys::AUDIT_ENTRY_PENDING)),
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
