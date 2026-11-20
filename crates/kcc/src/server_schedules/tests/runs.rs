//! Runs on a busy router, owners that can no longer run them, one router's queue and
//! the stop.

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::time::Duration;

use kcc_app::{
    brackets::Brackets,
    permissions::{Permission, Role},
    schedules::model::{PauseReason, ScheduleState},
};
use serde_json::json;
use tokio::{sync::Semaphore, task::yield_now, time::sleep};

use super::{
    MONDAY, SUNDAY, monday_backup,
    rig::{Rig, TestResult, schedule},
    skipped,
    stub::Stub,
    succeeded,
};
use crate::server_schedules::{lines::LineKind, owner::Lookup};

/// Todo 13: a router busy three times runs on the fourth try, a minute apart, in one run.
#[tokio::test(start_paused = true)]
async fn a_busy_router_runs_on_the_fourth_try() -> TestResult {
    let rig = Rig::new(
        vec![monday_backup("00000000000000c5")?],
        MONDAY.saturating_sub(10),
    )
    .await?;
    let stub = Arc::new(Stub::busy(3));
    let scheduler = rig.start(Arc::<Stub>::clone(&stub));

    stub.called(4).await?;
    rig.recorder().received(1).await?;
    scheduler.finish(Duration::from_secs(60)).await;

    assert_eq!(stub.calls().len(), 4);
    assert_eq!(rig.states("00000000000000c5")?, vec![succeeded(MONDAY)]);
    assert!(
        rig.clock().now() >= MONDAY.saturating_add(180),
        "three minutes of retries"
    );
    Ok(())
}

/// Todo 13: a router busy past ten minutes ends the one begun run skipped `router_busy`.
#[tokio::test(start_paused = true)]
async fn a_router_busy_past_the_window_is_skipped_once() -> TestResult {
    let rig = Rig::new(
        vec![monday_backup("00000000000000c6")?],
        MONDAY.saturating_sub(10),
    )
    .await?;
    let stub = Arc::new(Stub::always_busy());
    let scheduler = rig.start(Arc::<Stub>::clone(&stub));

    rig.recorder().received(1).await?;
    sleep(Duration::from_hours(1)).await;
    scheduler.finish(Duration::from_secs(60)).await;

    assert_eq!(stub.calls().len(), 11, "tries at 0, 1, .., 10 minutes");
    assert_eq!(
        rig.states("00000000000000c6")?,
        vec![skipped(MONDAY, "router_busy")],
        "one record, begun once and finished"
    );
    Ok(())
}

/// Todo 13: a run taken from the queue after the busy window is skipped without its
/// action.
#[tokio::test(start_paused = true)]
async fn a_run_dequeued_after_the_window_is_skipped() -> TestResult {
    let rig = Rig::new(
        vec![
            monday_backup("00000000000000d1")?,
            monday_backup("00000000000000d2")?,
        ],
        MONDAY.saturating_sub(10),
    )
    .await?;
    let slow = BTreeMap::from([("00000000000000d1".to_owned(), Duration::from_mins(11))]);
    let stub = Arc::new(Stub::slow(slow));
    let scheduler = rig.start(Arc::<Stub>::clone(&stub));

    rig.recorder().received(2).await?;
    scheduler.finish(Duration::from_secs(60)).await;

    assert_eq!(stub.calls(), vec!["00000000000000d1".to_owned()]);
    assert_eq!(
        rig.states("00000000000000d2")?,
        vec![skipped(MONDAY, "router_busy")]
    );
    Ok(())
}

/// Todo 13: a disabled Web owner pauses the schedule `owner_unavailable`; nothing runs.
#[tokio::test(start_paused = true)]
async fn a_disabled_owner_pauses_the_schedule() -> TestResult {
    let rig = Rig::new(
        vec![monday_backup("00000000000000e1")?],
        MONDAY.saturating_sub(10),
    )
    .await?;
    rig.accounts().set("alice", Lookup::Disabled);
    let stub = Arc::new(Stub::default());
    let scheduler = rig.start(Arc::<Stub>::clone(&stub));

    rig.recorder().received(1).await?;
    sleep(Duration::from_hours(1)).await;
    scheduler.finish(Duration::from_secs(60)).await;

    assert!(stub.calls().is_empty(), "{:?}", stub.calls());
    assert!(matches!(
        rig.schedule_state("00000000000000e1")?,
        ScheduleState::Paused {
            reason: PauseReason::OwnerUnavailable,
            at: _
        }
    ));
    assert!(rig.runs("00000000000000e1")?.is_empty(), "no run begun");
    assert_eq!(
        rig.recorder().lines(),
        vec![(
            "00000000000000e1".to_owned(),
            LineKind::Paused {
                reason: PauseReason::OwnerUnavailable
            }
        )]
    );
    Ok(())
}

/// Todo 13: an owner whose role lost `Destructive` pauses a reboot `forbidden`.
#[tokio::test(start_paused = true)]
async fn a_role_without_destructive_pauses_a_reboot() -> TestResult {
    let reboot = schedule(
        "00000000000000e2",
        (&["mon"], 3, 0, "UTC"),
        &json!({"kind": "reboot"}),
        SUNDAY,
    )?;
    let rig = Rig::new(vec![reboot], MONDAY.saturating_sub(10)).await?;
    rig.roles().replace(vec![Role::new(
        "admin".to_owned(),
        Permission::ALL
            .into_iter()
            .filter(|permission| *permission != Permission::Destructive),
        vec!["*".to_owned()],
    )]);
    let stub = Arc::new(Stub::default());
    let scheduler = rig.start(Arc::<Stub>::clone(&stub));

    rig.recorder().received(1).await?;
    scheduler.finish(Duration::from_secs(60)).await;

    assert!(stub.calls().is_empty(), "{:?}", stub.calls());
    assert!(matches!(
        rig.schedule_state("00000000000000e2")?,
        ScheduleState::Paused {
            reason: PauseReason::Forbidden,
            at: _
        }
    ));
    Ok(())
}

/// Todo 13: two runs of one router run in order and never overlap.
#[tokio::test(start_paused = true)]
async fn runs_of_one_router_run_in_order() -> TestResult {
    let rig = Rig::new(
        vec![
            monday_backup("00000000000000f1")?,
            monday_backup("00000000000000f2")?,
        ],
        MONDAY.saturating_sub(10),
    )
    .await?;
    let slow = BTreeMap::from([
        ("00000000000000f1".to_owned(), Duration::from_secs(30)),
        ("00000000000000f2".to_owned(), Duration::from_secs(30)),
    ]);
    let stub = Arc::new(Stub::slow(slow));
    let scheduler = rig.start(Arc::<Stub>::clone(&stub));

    stub.called(2).await?;
    sleep(Duration::from_mins(5)).await;
    scheduler.finish(Duration::from_secs(60)).await;

    assert_eq!(
        stub.events(),
        vec![
            "start:00000000000000f1",
            "end:00000000000000f1",
            "start:00000000000000f2",
            "end:00000000000000f2"
        ]
    );
    assert_eq!(stub.most_at_once(), 1);
    Ok(())
}

/// Todo 13: after the stop, a slot that comes never runs.
#[tokio::test(start_paused = true)]
async fn the_stop_ends_admission() -> TestResult {
    let rig = Rig::new(
        vec![monday_backup("00000000000000f3")?],
        MONDAY.saturating_sub(300),
    )
    .await?;
    let stub = Arc::new(Stub::default());
    let scheduler = rig.start(Arc::<Stub>::clone(&stub));

    sleep(Duration::from_secs(1)).await;
    scheduler.finish(Duration::from_secs(60)).await;
    sleep(Duration::from_hours(1)).await;

    assert!(stub.calls().is_empty(), "{:?}", stub.calls());
    assert!(rig.runs("00000000000000f3")?.is_empty(), "no run begun");
    Ok(())
}

/// Todo 13: stopped while an action holds a bracket guard, the scheduler's task ends only
/// after the action released it.
#[tokio::test(start_paused = true)]
async fn the_stop_waits_for_the_bracket_in_progress() -> TestResult {
    let rig = Rig::new(
        vec![monday_backup("00000000000000f4")?],
        MONDAY.saturating_sub(5),
    )
    .await?;
    let (gate, brackets) = (Arc::new(Semaphore::new(0)), Brackets::default());
    let stub = Arc::new(Stub::gated(Arc::clone(&gate), brackets.clone()));
    let scheduler = rig.start(Arc::<Stub>::clone(&stub));

    stub.called(1).await?;
    let finishing = tokio::spawn(scheduler.finish(Duration::from_hours(1)));
    for _turn in 0_u8..10 {
        yield_now().await;
    }
    let held = (finishing.is_finished(), brackets.count());
    gate.add_permits(1);
    finishing.await?;

    assert_eq!(held, (false, 1), "the task waits while the guard is held");
    assert_eq!(brackets.count(), 0);
    Ok(())
}
