//! Slots against the wall clock: daylight-saving changes, clock steps, missed slots and
//! runs interrupted by a restart.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::schedules::ledger::{RunLedger, RunState, Trigger};
use serde_json::json;
use tokio::time::sleep;

use super::{
    DAY, FALL, MONDAY, SPRING, SUNDAY, WEDNESDAY, monday_backup,
    rig::{Rig, TestResult, schedule},
    skipped,
    stub::Stub,
    succeeded,
};
use crate::server_schedules::lines::LineKind;

/// Runs a Sunday 02:30 Berlin schedule from an hour before `slot` to three hours after
/// it, and asserts one run, of `slot`.
async fn berlin_fires_once(slot: i64) -> TestResult {
    let night = schedule(
        "00000000000000b1",
        (&["sun"], 2, 30, "Europe/Berlin"),
        &json!({"kind": "backup"}),
        slot.saturating_sub(DAY),
    )?;
    let rig = Rig::new(vec![night], slot.saturating_sub(3_600)).await?;
    let stub = Arc::new(Stub::default());
    let scheduler = rig.start(Arc::<Stub>::clone(&stub));

    stub.called(1).await?;
    sleep(Duration::from_hours(3)).await;
    scheduler.finish(Duration::from_secs(60)).await;

    assert_eq!(stub.calls().len(), 1, "one run");
    assert_eq!(rig.states("00000000000000b1")?, vec![succeeded(slot)]);
    Ok(())
}

/// Todo 13: the Berlin 2027-03-28 02:30 slot (in the gap) fires exactly once.
#[tokio::test(start_paused = true)]
async fn the_spring_gap_slot_fires_once() -> TestResult {
    berlin_fires_once(SPRING).await
}

/// Todo 13: the Berlin 2027-10-31 02:30 slot (in the fold) fires exactly once.
#[tokio::test(start_paused = true)]
async fn the_fall_fold_slot_fires_once() -> TestResult {
    berlin_fires_once(FALL).await
}

/// Todo 13: a wall clock stepped back 10 minutes after a fired slot runs it no second
/// time.
#[tokio::test(start_paused = true)]
async fn a_clock_stepped_back_repeats_no_slot() -> TestResult {
    let rig = Rig::new(
        vec![monday_backup("00000000000000c1")?],
        MONDAY.saturating_sub(60),
    )
    .await?;
    let stub = Arc::new(Stub::default());
    let scheduler = rig.start(Arc::<Stub>::clone(&stub));

    stub.called(1).await?;
    rig.clock().step(-600);
    sleep(Duration::from_hours(1)).await;
    scheduler.finish(Duration::from_secs(60)).await;

    assert_eq!(stub.calls().len(), 1, "no second run");
    assert_eq!(rig.states("00000000000000c1")?, vec![succeeded(MONDAY)]);
    Ok(())
}

/// Todo 13: a wall clock stepped 5 minutes past a slot skips it with one line.
#[tokio::test(start_paused = true)]
async fn a_clock_stepped_past_a_slot_skips_it() -> TestResult {
    let rig = Rig::new(
        vec![monday_backup("00000000000000c2")?],
        MONDAY.saturating_sub(120),
    )
    .await?;
    let stub = Arc::new(Stub::default());
    let scheduler = rig.start(Arc::<Stub>::clone(&stub));

    sleep(Duration::from_secs(1)).await;
    rig.clock().step(420);
    rig.recorder().received(1).await?;
    sleep(Duration::from_hours(1)).await;
    scheduler.finish(Duration::from_secs(60)).await;

    assert!(stub.calls().is_empty(), "{:?}", stub.calls());
    assert_eq!(
        rig.states("00000000000000c2")?,
        vec![skipped(MONDAY, "late")]
    );
    let lines = rig.recorder().lines();
    assert!(
        matches!(
            lines.as_slice(),
            [(_, LineKind::Missed { count: 1, time: _ })]
        ),
        "{lines:?}"
    );
    Ok(())
}

/// Todo 13: three missed slots are one ledger skip and one line naming 3.
#[tokio::test(start_paused = true)]
async fn three_missed_slots_are_one_skip_and_one_line() -> TestResult {
    let daily = schedule(
        "00000000000000c3",
        (&["mon", "tue", "wed"], 3, 0, "UTC"),
        &json!({"kind": "backup"}),
        SUNDAY,
    )?;
    let rig = Rig::new(vec![daily], WEDNESDAY.saturating_add(3_600)).await?;
    let stub = Arc::new(Stub::default());
    let scheduler = rig.start(Arc::<Stub>::clone(&stub));

    rig.recorder().received(1).await?;
    sleep(Duration::from_hours(1)).await;
    scheduler.finish(Duration::from_secs(60)).await;

    assert!(stub.calls().is_empty(), "{:?}", stub.calls());
    assert_eq!(
        rig.states("00000000000000c3")?,
        vec![skipped(WEDNESDAY, "late")]
    );
    let lines = rig.recorder().lines();
    assert!(
        matches!(
            lines.as_slice(),
            [(_, LineKind::Missed { count: 3, time: _ })]
        ),
        "{lines:?}"
    );
    Ok(())
}

/// Todo 13: a run found started at the start is reported once as interrupted and never
/// run again.
#[tokio::test(start_paused = true)]
async fn a_started_run_is_interrupted_and_not_rerun() -> TestResult {
    let rig = Rig::new(
        vec![monday_backup("00000000000000c4")?],
        MONDAY.saturating_add(30),
    )
    .await?;
    let _started: i64 = RunLedger::new(rig.state().clone()).begin(
        "00000000000000c4",
        Trigger::Slot(MONDAY),
        MONDAY,
    )?;
    let stub = Arc::new(Stub::default());
    let scheduler = rig.start(Arc::<Stub>::clone(&stub));

    rig.recorder().received(1).await?;
    sleep(Duration::from_hours(1)).await;
    scheduler.finish(Duration::from_secs(60)).await;

    assert!(stub.calls().is_empty(), "{:?}", stub.calls());
    assert_eq!(
        rig.states("00000000000000c4")?,
        vec![(Some(MONDAY), RunState::Interrupted)]
    );
    assert_eq!(
        rig.recorder().lines(),
        vec![("00000000000000c4".to_owned(), LineKind::Interrupted)]
    );
    Ok(())
}
