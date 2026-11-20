//! A preset that applies: kept unsaved, rolled back, busy, or failed before any change.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::{audit::ActorKind, schedules::ledger::RunOutcome, workflow::WorkflowError};
use kcc_testkit::FaultInjection;
use tokio::time::timeout;

use super::{Bench, FIRST, ID, SECOND, Setup, WAIT, lines, now};
use crate::server_schedules::{
    lines::LineKind,
    run::{Report, run_once},
    tests::rig::TestResult,
};

/// Todo 14: a ready preset is applied, verified and kept unsaved.
///
/// The fail-safe timer is disarmed and the lines stay in the running configuration only;
/// the run is audited as a success and reported with the preset's name; nothing is saved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ready_preset_is_applied_and_kept_unsaved() -> TestResult {
    let bench = Bench::start(Setup::default()).await?;
    bench.capture_office("dns-secure", &[FIRST, SECOND]).await?;
    bench.schedule(false)?;

    let report = bench.run().await?;

    let Report::Finished(RunOutcome::Succeeded { unsaved, checksum }) = report else {
        return Err(format!("{report:?}").into());
    };
    assert!(unsaved && checksum.is_some(), "{unsaved} {checksum:?}");
    assert!(!bench.target.recovery_armed(), "the fail-safe timer is off");
    let running = lines(&bench.target.running_config_text())?;
    let startup = lines(&bench.target.startup_config_text())?;
    for line in [FIRST, SECOND] {
        assert!(running.iter().any(|found| found == line), "{running:?}");
        assert!(!startup.iter().any(|found| found == line), "never saved");
    }
    let commands = bench.commands();
    assert!(
        !commands
            .iter()
            .any(|command| command.contains("save") || command.contains("fail-safe commit")),
        "{commands:?}"
    );
    let entries = bench.run_entries().await?;
    let [entry] = entries.as_slice() else {
        return Err(format!("one schedule.run entry: {entries:?}").into());
    };
    assert_eq!(
        (
            entry.actor.kind,
            entry.actor.id.as_str(),
            entry.outcome.as_str(),
            entry.target.as_deref()
        ),
        (
            ActorKind::System,
            "schedule:0000000000000e01",
            "success",
            Some("preset")
        )
    );
    assert_eq!(
        bench.recorder.lines(),
        vec![(
            ID.to_owned(),
            LineKind::PresetApplied {
                preset: "night".to_owned()
            }
        )]
    );
    assert_eq!(
        bench.recorder.jobs().len(),
        1,
        "the applier's job is claimed"
    );
    Ok(())
}

/// Todo 14: a failed verification is rolled back under the router's lease.
///
/// A line the router ignores fails verification and the run rolls the router back to its
/// saved configuration; it holds the router's lease until it returned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_verification_is_rolled_back_under_the_lease() -> TestResult {
    let bench = Bench::start(Setup {
        faults: FaultInjection::default().silent_noop_path(SECOND),
        ..Setup::default()
    })
    .await?;
    bench.capture_office("dns-secure", &[FIRST, SECOND]).await?;
    bench.schedule(false)?;
    let mut events = bench.actions.jobs().subscribe();

    let deps = Arc::clone(&bench.deps);
    let running = tokio::spawn(async move { run_once(&deps, ID, now()).await });
    drop(timeout(WAIT, events.recv()).await??);
    let mut stall = bench.target.stall();
    assert!(
        timeout(WAIT, stall.held()).await?,
        "a request of the run is held"
    );
    assert!(
        matches!(bench.reserve(), Err(WorkflowError::RouterBusy { actor: _ })),
        "the run holds the lease"
    );
    drop(stall);
    let report = timeout(WAIT, running).await??;

    assert_eq!(
        report,
        Report::Finished(RunOutcome::Failed {
            code: "preset_rolled_back".to_owned()
        })
    );
    assert_eq!(
        lines(&bench.target.running_config_text())?,
        lines(&bench.target.startup_config_text())?
    );
    assert!(
        bench
            .commands()
            .iter()
            .any(|command| command == "system configuration fail-safe rollback"),
        "{:?}",
        bench.commands()
    );
    drop(bench.reserve()?);
    Ok(())
}

/// Todo 14: a leased router makes the run busy before anything is sent.
///
/// A run-now is not tried again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_leased_router_is_busy() -> TestResult {
    let bench = Bench::start(Setup::default()).await?;
    bench.capture_office("dns-secure", &[FIRST]).await?;
    bench.schedule(false)?;
    let held = bench.reserve()?;

    let report = bench.run().await?;

    assert_eq!(
        report,
        Report::Finished(RunOutcome::Skipped {
            reason: "router_busy".to_owned()
        })
    );
    assert_eq!(bench.commands(), Vec::<String>::new());
    drop(held);
    Ok(())
}

/// Todo 14: a failed preparation is not rolled back.
///
/// The fail-safe timer was refused, and so was its cleanup: the run fails saying that the
/// timer may be armed, sends no rollback and leaves the router's lease free.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_preparation_is_not_rolled_back() -> TestResult {
    let bench = Bench::start(Setup {
        faults: FaultInjection::default()
            .fail_parse_matching("system configuration fail-safe timer", 2),
        ..Setup::default()
    })
    .await?;
    bench.capture_office("dns-secure", &[FIRST]).await?;
    bench.schedule(false)?;

    let report = bench.run().await?;

    assert_eq!(
        report,
        Report::Finished(RunOutcome::Failed {
            code: "preset_failed_armed".to_owned()
        })
    );
    let commands = bench.commands();
    assert!(
        !commands
            .iter()
            .any(|command| command.contains("rollback") || command == "system reboot"),
        "{commands:?}"
    );
    drop(bench.reserve()?);
    Ok(())
}
