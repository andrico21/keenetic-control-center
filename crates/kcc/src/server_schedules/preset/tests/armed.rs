//! A preparation that failed with the fail-safe timer possibly armed: the run keeps the
//! router's lease until the timer has run out on the apply clock, and only then.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{schedules::ledger::RunOutcome, workflow::WorkflowError};
use kcc_testkit::FaultInjection;
use tokio::{task::JoinHandle, time::timeout};

use super::{Bench, FIRST, HandClock, ID, SECOND, Setup, WAIT, now};
use crate::server_schedules::{
    run::{Report, run_once},
    tests::rig::TestResult,
};

/// Whether `home`'s lease is taken.
fn busy(bench: &Bench) -> bool {
    matches!(bench.reserve(), Err(WorkflowError::RouterBusy { actor: _ }))
}

/// The outcome of a run that failed with `code`.
fn failed(code: &str) -> Report {
    Report::Finished(RunOutcome::Failed {
        code: code.to_owned(),
    })
}

/// A bench whose router meets `faults`, on `clock`, with the preset schedule stored.
async fn bench(faults: FaultInjection, clock: &Arc<HandClock>) -> TestResult<Bench> {
    let bench = Bench::start(Setup {
        faults,
        clock: Arc::<HandClock>::clone(clock),
        ..Setup::default()
    })
    .await?;
    bench.capture_office("dns-secure", &[FIRST, SECOND]).await?;
    bench.schedule(false)?;
    Ok(bench)
}

/// Starts the preset run and waits until it waits on `clock` for the fail-safe timer,
/// with the router's lease taken; answers the run and how long it waits. A run that ends
/// before that is an error.
pub(super) async fn held(
    bench: &Bench,
    clock: &HandClock,
) -> TestResult<(JoinHandle<Report>, Duration)> {
    let deps = Arc::clone(&bench.deps);
    let mut running = tokio::spawn(async move { run_once(&deps, ID, now()).await });
    let left = tokio::select! {
        left = clock.waiting_longer(Duration::from_mins(1)) => left?,
        ended = &mut running => {
            let lease = if busy(bench) { "taken" } else { "free" };
            let report = ended?;
            return Err(format!("the run ended with the lease {lease}: {report:?}").into());
        }
    };
    assert!(busy(bench), "the lease is kept while the timer may run");
    Ok((running, left))
}

/// Todo 21: an arm whose reply was lost keeps the lease until the timer ran out.
///
/// The router arms its fail-safe timer and then drops every connection, so neither the
/// arm nor its cleanup is confirmed: the run fails saying that the timer may be armed,
/// and the router's lease stays taken until the timer has run out on the apply clock,
/// one second before that included.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_arm_keeps_the_lease_until_the_timer_ran_out() -> TestResult {
    let clock = Arc::new(HandClock::default());
    let faults = FaultInjection::default()
        .disconnect_after_parse("system configuration fail-safe timer".to_owned());
    let bench = bench(faults, &clock).await?;
    let (running, left) = held(&bench, &clock).await?;
    assert!(bench.target.recovery_armed(), "the router's timer runs");

    clock.advance(left.saturating_sub(Duration::from_secs(1)));
    assert!(busy(&bench), "the lease is kept until the timer ran out");
    clock.advance(Duration::from_secs(1));
    let report = timeout(WAIT, running).await??;

    assert_eq!(report, failed("preset_failed_armed"));
    drop(bench.reserve()?);
    Ok(())
}

/// Todo 21: a refused arm whose cleanup succeeded holds nothing.
///
/// The timer is known to be off, so the run fails without waiting for it and the lease is
/// free as soon as the run ended; the apply clock never moves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disarmed_failure_frees_the_lease_at_once() -> TestResult {
    let clock = Arc::new(HandClock::default());
    let faults =
        FaultInjection::default().fail_parse_matching("system configuration fail-safe timer", 1);
    let bench = bench(faults, &clock).await?;

    let report = bench.run().await?;

    assert_eq!(report, failed("preset_failed"));
    assert!(!bench.target.recovery_armed());
    drop(bench.reserve()?);
    Ok(())
}
