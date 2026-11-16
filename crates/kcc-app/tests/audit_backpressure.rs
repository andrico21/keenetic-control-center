//! Back-pressure of the audit queue while another process holds the append lock.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

use core::{error::Error, time::Duration};

use kcc_app::{
    audit::{AUDIT_FILE_NAME, Actor, ActorKind, AuditError, AuditEvent, AuditLog, verify_chain},
    persist::StateStore,
};
use tempfile::TempDir;
use tokio::{
    task::{JoinSet, yield_now},
    time::{Instant, timeout},
};

type TestResult = Result<(), Box<dyn Error>>;

/// More entries than the old 128-slot queue held.
const FLOOD: u64 = 300;
/// Slots of the bounded entry point.
const SLOTS: u64 = 128;

fn event(index: u64) -> AuditEvent {
    AuditEvent::new(
        1_700_000_000_u64.saturating_add(index),
        Actor::new(ActorKind::System, "backpressure-test".to_owned()),
        "test.backpressure".to_owned(),
    )
    .with_result("success".to_owned(), format!("flood-{index}"))
}

/// Lets every spawned task run up to its first wait.
async fn settle() {
    for _round in 0_u8..8_u8 {
        yield_now().await;
    }
}

/// B-04: entries submitted on a saturated queue are queued at once, never held back.
///
/// Another process holds the append lock; the entries are written in submission order
/// once the lock is free.
#[tokio::test(start_paused = true)]
async fn entries_submitted_while_saturated_are_queued_at_once_and_written_in_order() -> TestResult {
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let other_process = StateStore::open(state.dir())?;
    let held = other_process.try_lock(AUDIT_FILE_NAME)?;
    let audit = AuditLog::spawn(&state)?;
    let mut appends = JoinSet::new();
    for index in 0..FLOOD {
        let writer = audit.clone();
        drop(appends.spawn(async move { writer.append(event(index)).await }));
        yield_now().await;
    }
    settle().await;

    let queued = audit.flush(Duration::ZERO).await;

    assert_eq!(
        u64::try_from(queued)?,
        FLOOD,
        "every entry is queued at once"
    );
    drop(held);
    assert_eq!(audit.flush(Duration::from_secs(60)).await, 0, "all written");
    while let Some(joined) = appends.join_next().await {
        drop(joined?);
    }
    let written = verify_chain(state.dir())?
        .into_iter()
        .map(|entry| entry.request_id)
        .collect::<Vec<_>>();
    let submitted = (0..FLOOD)
        .map(|index| format!("flood-{index}"))
        .collect::<Vec<_>>();
    assert_eq!(written, submitted, "written in submission order");
    Ok(())
}

/// B-04: a bounded submit on a saturated queue answers `QueueFull` at its own limit.
///
/// Another process holds the append lock and every slot is taken; the refused entry is
/// never written. A cancelled bounded wait holds no slot, and every slot comes back once
/// the writer has written its entry.
#[tokio::test(start_paused = true)]
async fn a_bounded_submit_on_a_saturated_queue_times_out_within_its_limit() -> TestResult {
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let other_process = StateStore::open(state.dir())?;
    let held = other_process.try_lock(AUDIT_FILE_NAME)?;
    let audit = AuditLog::spawn(&state)?;
    let limit = Duration::from_secs(5);
    let mut queued = Vec::new();
    for index in 0..SLOTS {
        queued.push(audit.submit_within(event(index), limit).await?);
    }
    let unbounded = audit.submit(event(SLOTS))?;
    let started = Instant::now();

    let refused = audit
        .submit_within(event(SLOTS.saturating_add(1)), limit)
        .await;

    assert!(matches!(refused, Err(AuditError::QueueFull)), "{refused:?}");
    let waited = started.elapsed();
    assert!(
        waited >= limit && waited <= limit.saturating_add(Duration::from_millis(10)),
        "answered at its limit: {waited:?}"
    );
    let cancelled = timeout(
        Duration::from_secs(1),
        audit.submit_within(event(SLOTS.saturating_add(2)), limit),
    )
    .await;
    assert!(cancelled.is_err(), "the outer wait ends first");
    drop(held);
    for mut pending in queued {
        drop(pending.wait(Duration::from_secs(60)).await?);
    }
    drop(unbounded);
    assert_eq!(audit.flush(Duration::from_secs(60)).await, 0);
    let written = verify_chain(state.dir())?
        .into_iter()
        .map(|entry| entry.request_id)
        .collect::<Vec<_>>();
    let expected = (0..=SLOTS)
        .map(|index| format!("flood-{index}"))
        .collect::<Vec<_>>();
    assert_eq!(written, expected, "the refused entry is never written");
    let held_again = other_process.try_lock(AUDIT_FILE_NAME)?;
    for index in 0..SLOTS {
        drop(audit.submit_within(event(index), Duration::ZERO).await?);
    }
    drop(held_again);
    Ok(())
}
