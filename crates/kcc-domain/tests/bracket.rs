//! The shared safety bracket: what it sends, what a failure says about the recovery timer,
//! and the process-wide count of open brackets.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

extern crate alloc;

use alloc::sync::Arc;
use core::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use std::fs;

use kcc_app::{
    audit::{AUDIT_FILE_NAME, Actor, ActorKind, AuditEvent, verify_chain},
    permissions::{Permission, Role},
    persist::StateStore,
    workflow::{ChangeResult, ChangeSet, WorkflowError},
};
use kcc_domain::{
    RouterCtx,
    configuration::{
        SafetyMode,
        bracket::{ArmedFate, guarded},
        recovery::Failure,
    },
    system,
};
use kcc_testkit::{
    bracket::{Fate, Recovery},
    model::Firmware,
};
use tokio::{
    task::{JoinSet, yield_now},
    time::timeout,
};

use crate::support::{Fixture, PROFILES, TestResult};

/// The system modes the fake reports: the fail-safe timer and, where the firmware reports
/// the mode, the scheduled reboot.
const MODES: [&str; 2] = ["router", "extender"];

/// What `work` does inside the bracket.
#[derive(Clone, Copy, Debug)]
enum Work {
    /// Applies a description change.
    Apply,
    /// Fails before sending anything with a sentinel error.
    Fail,
}

/// The shared bracket fate the router is made to give (`None`: no fault), the work, and
/// the failure's fate; `None` fate rows are not armed and must carry the original error.
type Row = (Option<Fate>, Work, Option<ArmedFate>);

const ROWS: [Row; 5] = [
    // The arm is refused, the disarm accepted: nothing armed, nothing applied.
    (Some(Fate::ArmRefused), Work::Apply, None),
    // Arm and disarm refused: nothing sent, the timer may be armed.
    (Some(Fate::NotSent), Work::Apply, Some(ArmedFate::NotSent)),
    // The work fails, the disarm is accepted: the original error, not armed.
    (None, Work::Fail, None),
    // The work applied, the disarm is refused.
    (
        Some(Fate::DisarmRefused),
        Work::Apply,
        Some(ArmedFate::Applied),
    ),
    // The work failed, the disarm is refused.
    (
        Some(Fate::DisarmRefused),
        Work::Fail,
        Some(ArmedFate::Unknown),
    ),
];

/// The work's line; the work is sent over RCI, so no parser fault matches it.
const WORK_LINE: &str = "system description bracketed";

/// The parser lines the router saw after `before` requests.
fn commands_after(fixture: &Fixture, before: usize) -> Vec<String> {
    fixture
        .handle()
        .request_log()
        .into_iter()
        .skip(before)
        .filter_map(|record| record.command().map(str::to_owned))
        .collect()
}

/// The arm and disarm lines of `mode`.
const fn lines(mode: SafetyMode) -> [&'static str; 2] {
    match mode {
        SafetyMode::Router => Recovery::FailSafeTimer.lines(),
        SafetyMode::ScheduledReboot => Recovery::ScheduledReboot.lines(),
        _ => ["unknown arm", "unknown disarm"],
    }
}

/// Terminates the fixture's audit writer: its active file stops verifying, so the next
/// append is a fatal writer failure.
async fn kill_audit(fixture: &Fixture) -> TestResult {
    fs::write(fixture.state_dir().join(AUDIT_FILE_NAME), b"not an entry\n")?;
    let event = AuditEvent::new(
        1,
        Actor::new(ActorKind::System, "test".to_owned()),
        "t".to_owned(),
    )
    .with_result("success".to_owned(), "audit-1".to_owned());
    let failed = fixture.audit().append(event).await;
    if failed.is_ok() || fixture.audit().is_alive() {
        return Err("the audit writer survived a corrupt file".into());
    }
    Ok(())
}

/// Work that panics inside the bracket.
#[expect(clippy::panic, reason = "the bracket's work panics on purpose")]
fn work_panics() -> Result<((), bool), WorkflowError> {
    panic!("the bracket's work panics")
}

/// Runs one bracket of `work` with an always-held request.
async fn run(
    changes: &mut ChangeSet,
    fixture: &Fixture,
    mode: SafetyMode,
    work: Work,
) -> TestResult<Result<bool, Failure<WorkflowError>>> {
    let plan = system::plan_description(fixture.context(), "bracketed")?;
    let request = system::change_request(&plan)?;
    Ok(guarded(
        changes,
        fixture.context(),
        mode,
        Permission::Write,
        || true,
        async move |set: &mut ChangeSet, _router: &RouterCtx| match work {
            Work::Apply => {
                let _applied: ChangeResult = set.apply(request).await?;
                Ok((true, true))
            }
            Work::Fail => Err(WorkflowError::SaveTimeout),
        },
    )
    .await)
}

#[tokio::test]
async fn a_failure_says_whether_the_timer_may_still_be_armed() -> TestResult {
    for firmware in PROFILES {
        for system_mode in MODES {
            for (refused, work, fate) in ROWS {
                let recovery = Recovery::for_mode(system_mode);
                let faults =
                    refused.map_or_default(|injected| injected.faults(recovery, WORK_LINE));
                let fixture = Fixture::spawn_mode(firmware, system_mode, faults).await?;
                let mut changes = fixture.changes().await?;
                let mode = SafetyMode::for_change(&changes)?;
                let before = fixture.handle().request_log().len();

                let outcome = run(&mut changes, &fixture, mode, work).await?;

                let label = format!("{firmware} {system_mode} {mode:?} {refused:?} {work:?}");
                let failure = outcome
                    .err()
                    .ok_or_else(|| format!("{label}: bracket succeeded"))?;
                assert_eq!(failure.fate(), fate, "{label}");
                assert_eq!(failure.is_armed(), fate.is_some(), "{label}");
                assert_eq!(commands_after(&fixture, before), lines(mode), "{label}");
                if fate.is_none() {
                    assert!(!fixture.handle().recovery_armed(), "{label}: fake armed");
                }
                if matches!((fate, work), (None, Work::Fail)) {
                    assert!(
                        matches!(failure.into_source(), WorkflowError::SaveTimeout),
                        "{label}: the original error"
                    );
                }
                drop(changes);
                fixture.shutdown().await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn an_unheld_request_or_a_dead_audit_writer_arms_nothing() -> TestResult {
    for firmware in PROFILES {
        for dead_audit in [false, true] {
            let fixture = Fixture::spawn(firmware).await?;
            let mut changes = fixture.changes().await?;
            if dead_audit {
                kill_audit(&fixture).await?;
            }
            // Only the dead-audit case holds its request, so that its refusal is the audit's.
            let holds = dead_audit;
            let before = fixture.handle().request_count();

            let outcome = guarded(
                &mut changes,
                fixture.context(),
                SafetyMode::Router,
                Permission::Write,
                move || holds,
                async |_changes: &mut ChangeSet, _router: &RouterCtx| {
                    Ok::<_, WorkflowError>(((), true))
                },
            )
            .await;

            let failure = outcome.err().ok_or("refused bracket succeeded")?;
            assert_eq!(failure.fate(), None, "{firmware} dead audit {dead_audit}");
            if dead_audit {
                assert!(matches!(failure.into_source(), WorkflowError::Audit(_)));
            }
            assert_eq!(fixture.handle().request_count(), before, "{firmware}: sent");
            assert_eq!(fixture.workflow().brackets().count(), 0);
            drop(changes);
            fixture.shutdown().await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_write_only_role_runs_a_whole_bracket() -> TestResult {
    let role = Role::new(
        "writer".to_owned(),
        [Permission::Read, Permission::Write],
        vec!["*".to_owned()],
    );
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let mut changes = fixture.changes_as(&role).await?;
        let plan = system::plan_description(fixture.context(), "writer")?;
        let request = system::change_request(&plan)?;
        let workflow = Arc::clone(fixture.workflow());
        let before = fixture.handle().request_log().len();

        let inside = guarded(
            &mut changes,
            fixture.context(),
            SafetyMode::Router,
            Permission::Write,
            || true,
            async move |set: &mut ChangeSet, _router: &RouterCtx| {
                let _applied: ChangeResult = set.apply(request).await?;
                Ok::<_, WorkflowError>((workflow.brackets().count(), true))
            },
        )
        .await
        .map_err(|failure| format!("{firmware}: {:?}", failure.into_source()))?;

        assert_eq!(inside, 1, "{firmware}: counted inside the work");
        assert_eq!(
            fixture.workflow().brackets().count(),
            0,
            "{firmware}: after"
        );
        assert_eq!(
            commands_after(&fixture, before),
            lines(SafetyMode::Router),
            "{firmware}"
        );
        assert!(!fixture.handle().recovery_armed());
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_panicking_bracket_leaves_the_count() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let mut changes = fixture.changes().await?;
        let router = fixture.context().clone();
        let workflow = Arc::clone(fixture.workflow());
        let inside = Arc::new(AtomicUsize::new(usize::MAX));
        let seen = Arc::clone(&inside);

        let task = tokio::spawn(async move {
            let outcome: Result<(), Failure<WorkflowError>> = guarded(
                &mut changes,
                &router,
                SafetyMode::Router,
                Permission::Write,
                || true,
                async move |_changes: &mut ChangeSet, _router: &RouterCtx| {
                    seen.store(workflow.brackets().count(), Ordering::SeqCst);
                    work_panics()
                },
            )
            .await;
            drop(outcome);
        })
        .await;

        assert!(task.is_err_and(|error| error.is_panic()), "{firmware}");
        assert_eq!(
            inside.load(Ordering::SeqCst),
            1,
            "{firmware}: counted inside"
        );
        assert_eq!(fixture.workflow().brackets().count(), 0, "{firmware}: left");
        fixture.shutdown().await?;
    }
    Ok(())
}

/// More entries than the old 128-slot audit queue held.
const FLOOD: u64 = 200;

/// B-04: a bracket arms, works and disarms with a saturated audit queue.
///
/// Another process holds the append lock and more entries are queued than the old
/// 128-slot channel held; the bracket's receipts stay pending and every entry is written,
/// in order, once the lock is free.
#[tokio::test]
async fn a_bracket_disarms_with_a_saturated_audit_queue() -> TestResult {
    let fixture = Fixture::spawn(Firmware::V5_1).await?;
    let mut changes = fixture.changes().await?;
    let other_process = StateStore::open(&fixture.state_dir())?;
    let held = other_process.try_lock(AUDIT_FILE_NAME)?;
    let mut flood = JoinSet::new();
    for index in 0..FLOOD {
        let audit = fixture.audit().clone();
        let event = AuditEvent::new(
            index,
            Actor::new(ActorKind::System, "flood".to_owned()),
            "test.flood".to_owned(),
        )
        .with_result("success".to_owned(), format!("flood-{index}"));
        drop(flood.spawn(async move { audit.append(event).await }));
        yield_now().await;
    }
    let before = fixture.handle().request_log().len();

    let bracket = timeout(
        Duration::from_secs(90),
        run(&mut changes, &fixture, SafetyMode::Router, Work::Apply),
    )
    .await
    .map_err(|_elapsed| "the bracket hung on the saturated audit queue")?;

    let applied = bracket?.map_err(|failure| format!("{:?}", failure.into_source()))?;
    assert!(applied, "the work applied");
    assert_eq!(
        commands_after(&fixture, before),
        lines(SafetyMode::Router),
        "armed and disarmed"
    );
    assert!(!fixture.handle().recovery_armed(), "the timer is off");
    assert!(changes.audit_pending(), "its receipts are still queued");
    drop(held);
    assert_eq!(fixture.audit().flush(Duration::from_secs(60)).await, 0);
    flood.abort_all();
    let written = verify_chain(&fixture.state_dir())?
        .into_iter()
        .map(|entry| entry.request_id)
        .collect::<Vec<_>>();
    let expected = (0..FLOOD)
        .map(|index| format!("flood-{index}"))
        .collect::<Vec<_>>();
    assert_eq!(written.get(..expected.len()), Some(expected.as_slice()));
    assert!(
        written.len() > expected.len(),
        "the bracket's entries follow"
    );
    drop(changes);
    fixture.shutdown().await?;
    Ok(())
}
