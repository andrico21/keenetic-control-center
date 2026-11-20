//! A rollback the router refuses: the run keeps the router's lease until the fail-safe
//! timer has run out on the apply clock, then reports what `show last-change` says.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{schedules::ledger::RunOutcome, workflow::WorkflowError};
use kcc_testkit::FaultInjection;
use tokio::{task::JoinHandle, time::timeout};

use super::{Bench, FIRST, HandClock, ID, SECOND, Setup, WAIT, now};
use crate::server_schedules::{
    run::{Report, run_once},
    tests::rig::{ROUTER, TestResult},
};

/// A run whose verification fails and whose rollback the router refuses, started and
/// waiting on `clock` for the fail-safe timer; answers the run and how long it waits.
async fn held(bench: &Bench, clock: &HandClock) -> TestResult<(JoinHandle<Report>, Duration)> {
    bench.capture_office("dns-secure", &[FIRST, SECOND]).await?;
    bench.schedule(false)?;
    let deps = Arc::clone(&bench.deps);
    let running = tokio::spawn(async move { run_once(&deps, ID, now()).await });
    let left = clock.waiting_longer(Duration::from_mins(1)).await?;
    assert!(
        matches!(bench.reserve(), Err(WorkflowError::RouterBusy { actor: _ })),
        "the run keeps the lease while the fail-safe timer runs"
    );
    assert!(
        bench
            .commands()
            .iter()
            .any(|command| command == "system configuration fail-safe rollback"),
        "the rollback was sent"
    );
    Ok((running, left))
}

/// A bench whose router ignores [`SECOND`] and refuses the rollback, on `clock`.
async fn refusing(clock: &Arc<HandClock>) -> TestResult<Bench> {
    let faults = FaultInjection::default()
        .silent_noop_path(SECOND)
        .fail_parse_matching("system configuration fail-safe rollback", 1);
    Bench::start(Setup {
        faults,
        clock: Arc::<HandClock>::clone(clock),
        ..Setup::default()
    })
    .await
}

/// Todo 14: a refused rollback reports a restored router after a restart.
///
/// The router restarts with its saved configuration while the run waits; once the timer
/// ran out on the apply clock, the run reports the router restored and releases the lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_rollback_reports_a_restored_router() -> TestResult {
    let clock = Arc::new(HandClock::default());
    let bench = refusing(&clock).await?;
    let (running, left) = held(&bench, &clock).await?;

    let client = bench.actions.registry().client(ROUTER).await?;
    drop(client.parse("system reboot").await?);
    clock.advance(left);
    let report = timeout(WAIT, running).await??;

    assert_eq!(
        report,
        Report::Finished(RunOutcome::Failed {
            code: "preset_restored".to_owned()
        })
    );
    drop(bench.reserve()?);
    Ok(())
}

/// Todo 14: a refused rollback with the lines left reports an unknown state.
///
/// The scheduled lines are still unsaved once the timer ran out on the apply clock; the
/// run says so and releases the lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_rollback_with_lines_left_reports_an_unknown_state() -> TestResult {
    let clock = Arc::new(HandClock::default());
    let bench = refusing(&clock).await?;
    let (running, left) = held(&bench, &clock).await?;

    clock.advance(left);
    let report = timeout(WAIT, running).await??;

    assert_eq!(
        report,
        Report::Finished(RunOutcome::Failed {
            code: "preset_state_unknown".to_owned()
        })
    );
    drop(bench.reserve()?);
    Ok(())
}
