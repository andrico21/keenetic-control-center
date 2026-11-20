//! The scheduler's loop under tokio's paused clock with a stepped wall clock and stub
//! actions; no sockets. Action tests over a fake router are in `actions/tests.rs`.

mod clock;
pub(crate) mod rig;
mod runs;
pub(crate) mod stub;

use kcc_app::schedules::{ledger::RunState, model::Schedule};
use serde_json::json;

use self::rig::{TestResult, schedule};

/// 2027-03-28T01:30:00Z: Sunday 02:30 in Berlin falls into the spring-forward gap and
/// runs at 03:30 CEST.
const SPRING: i64 = 1_806_197_400;

/// 2027-10-31T00:30:00Z: Sunday 02:30 in Berlin occurs twice; the earlier instant runs.
const FALL: i64 = 1_824_942_600;

/// 2027-01-04T03:00:00Z, a Monday.
const MONDAY: i64 = 1_799_031_600;

/// A day.
const DAY: i64 = 86_400;

/// A day before [`MONDAY`]: when the schedules were last changed.
const SUNDAY: i64 = MONDAY - DAY;

/// The third of three missed daily slots from [`MONDAY`].
const WEDNESDAY: i64 = MONDAY + 2 * DAY;

/// A backup every Monday at 03:00 UTC, last changed a day before [`MONDAY`].
fn monday_backup(id: &str) -> TestResult<Schedule> {
    schedule(
        id,
        (&["mon"], 3, 0, "UTC"),
        &json!({"kind": "backup"}),
        SUNDAY,
    )
}

/// A done run of `slot`.
fn succeeded(slot: i64) -> (Option<i64>, RunState) {
    (
        Some(slot),
        RunState::Succeeded {
            unsaved: false,
            checksum: None,
        },
    )
}

/// A run of `slot` skipped for `reason`.
fn skipped(slot: i64, reason: &str) -> (Option<i64>, RunState) {
    (
        Some(slot),
        RunState::Skipped {
            reason: reason.to_owned(),
        },
    )
}
