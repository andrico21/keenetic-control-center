//! The run-now tracker under tokio's paused clock, the next slots over a temporary state
//! directory, and the refusal mapping; no router.

use core::{error::Error, time::Duration};

use kcc_app::{
    persist::StateStore,
    schedules::{
        ledger::{RunLedger, Trigger},
        model::{PauseReason, ScheduleState},
        store::SchedulesDocument,
    },
};
use kcc_web::admin_scheduled::ScheduleRefusal;
use serde_json::json;
use tempfile::TempDir;
use tokio::{
    sync::oneshot,
    time::{sleep, timeout},
};

use super::{Runs, closest, refusal, upcoming};
use crate::server_schedules::{
    eligible,
    preset::PresetRefusal,
    tests::rig::{ROUTER, schedule},
};

/// Test result.
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// 2027-01-04T03:00:00Z, a Monday.
const MONDAY: i64 = 1_799_031_600;

/// An hour.
const HOUR: i64 = 3_600;

/// A day.
const DAY: i64 = 86_400;

/// Every day of the week.
const DAILY: &[&str] = &["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

/// The second router.
const OFFICE: &str = "office";

/// Todo 15: the dashboard's next slot is the earliest of a router's active schedules
/// after now, and after the slot the ledger last fired.
#[test]
fn the_next_slot_is_the_earliest_active_one_after_now_and_the_last_fired() -> TestResult {
    let directory = TempDir::new()?;
    let state = StateStore::open(&directory.path().join("state"))?;
    let backup = json!({"kind": "backup"});
    let mut paused = schedule("000000000000000c", (DAILY, 2, 30, "UTC"), &backup, 0)?;
    paused.state = ScheduleState::Paused {
        reason: PauseReason::Manual,
        at: 0,
    };
    let mut elsewhere = schedule("000000000000000d", (&["mon"], 3, 0, "UTC"), &backup, 0)?;
    OFFICE.clone_into(&mut elsewhere.router);
    let mut document = SchedulesDocument::default();
    document.schedules = vec![
        schedule("000000000000000a", (DAILY, 3, 0, "UTC"), &backup, 0)?,
        schedule("000000000000000b", (&["mon"], 5, 0, "UTC"), &backup, 0)?,
        paused,
        elsewhere,
    ];
    state.write(&document)?;
    let fired = RunLedger::new(state.clone());
    let _: i64 = fired.begin("000000000000000d", Trigger::Slot(MONDAY), MONDAY)?;

    let early = upcoming(&state, MONDAY - HOUR);
    let later = upcoming(&state, MONDAY + 60);

    let home = |name: &str, slot: i64| (ROUTER.to_owned(), (name.to_owned(), slot));
    let office = (
        OFFICE.to_owned(),
        ("job-000000000000000d".to_owned(), MONDAY + 7 * DAY),
    );
    assert_eq!(
        early.into_iter().collect::<Vec<_>>(),
        vec![home("job-000000000000000a", MONDAY), office.clone()]
    );
    assert_eq!(
        later.into_iter().collect::<Vec<_>>(),
        vec![home("job-000000000000000b", MONDAY + 2 * HOUR), office]
    );
    Ok(())
}

/// Todo 15: closing the tracker waits for a run started now and admits no other.
#[tokio::test(start_paused = true)]
async fn closing_waits_for_the_runs_and_admits_none_after() -> TestResult {
    let runs = Runs::new();
    let (done, mut ended) = oneshot::channel();
    let started = runs.spawn(async move {
        sleep(Duration::from_secs(5)).await;
        done.send(()).unwrap_or_default();
    });

    runs.close(Duration::from_secs(10)).await;

    assert!(started, "an open tracker admits the run");
    assert_eq!(ended.try_recv(), Ok(()), "the run ended first");
    assert!(!runs.spawn(async {}), "a closed tracker admits none");
    Ok(())
}

/// Todo 15: a run still going when the grace ends runs on, never aborted.
#[tokio::test(start_paused = true)]
async fn a_run_past_the_grace_runs_on_detached() -> TestResult {
    let runs = Runs::new();
    let (release, released) = oneshot::channel::<()>();
    let (done, ended) = oneshot::channel();
    assert!(runs.spawn(async move {
        drop(released.await);
        done.send(()).unwrap_or_default();
    }));

    runs.close(Duration::from_secs(1)).await;

    release.send(()).map_err(|()| "the run was aborted")?;
    timeout(Duration::from_secs(10), ended).await??;
    Ok(())
}

/// Todo 15: each check refusal reads as the page's refusal of its code, and a code the
/// page does not know as the closest one.
#[test]
fn a_refusal_reads_as_the_page_refusal_of_its_code() {
    let preset = eligible::ScheduleRefusal::Preset(PresetRefusal::WireGuardKey);
    assert_eq!(refusal(preset), ScheduleRefusal::WireguardKey);
    assert_eq!(
        refusal(eligible::ScheduleRefusal::PolicyUnknown),
        ScheduleRefusal::PolicyUnknown
    );
    assert_eq!(
        closest("new_reason", true),
        ScheduleRefusal::PresetUnavailable
    );
    assert_eq!(closest("new_reason", false), ScheduleRefusal::Forbidden);
}
