//! One run of one schedule, from admission to the line that reports it.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{
    permissions::Role,
    schedules::{
        ledger::{RunOutcome, Trigger},
        model::{Action, PauseReason, Schedule},
    },
};
use tokio::{task::spawn_blocking, time::sleep};

use super::{
    RunDeps, TARGET,
    actions::{ActionResult, Call},
    lines::{Line, LineKind},
    record::{self, Admission},
    slots::within_window,
};

/// How a run ended, for a run-now caller.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub(crate) enum Report {
    /// Nothing ran: the schedule is gone or paused, or the slot already fired.
    Dropped,
    /// The schedule was paused for this reason instead.
    Paused(PauseReason),
    /// The run ended with this outcome.
    Finished(RunOutcome),
}

/// Runs schedule `id` once for `trigger`.
///
/// It re-reads the schedule and its owner (pausing it when the owner can no longer run
/// it), records the run as started, carries out the action, records the outcome, audits
/// it as `schedule.run` and reports it.
///
/// A slot is dropped when the schedule is no longer active or the slot already fired; a
/// slot taken more than the busy window after its time is skipped `router_busy` without
/// its action, and a busy router is tried again every `busy_retry` within that window.
/// A run-now is never retried.
// NOT cancel-safe: dropped after its record is begun, the run stays `started` and is
// reported as interrupted at the next start; dropped during the action, see the action.
pub(crate) async fn run_once(deps: &Arc<RunDeps>, id: &str, trigger: Trigger) -> Report {
    let now = deps.now();
    let (shared, owned_id, owned_trigger) = (Arc::clone(deps), id.to_owned(), trigger.clone());
    let admitted = spawn_blocking(move || record::admit(&shared, &owned_id, &owned_trigger, now))
        .await
        .unwrap_or_else(|error| {
            tracing::error!(target: TARGET, %error, "a run's admission did not finish");
            Admission::Dropped
        });
    match admitted {
        Admission::Dropped => Report::Dropped,
        Admission::Paused(schedule, reason) => {
            record::audit(
                deps,
                &schedule,
                ("schedule.pause", "success"),
                record::pause_params(&schedule, reason),
            );
            deps.report(Line::new(&schedule, LineKind::Paused { reason }));
            Report::Paused(reason)
        }
        Admission::Begun {
            schedule,
            role,
            started_at,
        } => {
            let late =
                matches!(trigger, Trigger::Slot(slot) if !within_window(slot, now, window(deps)));
            let result = if late {
                ActionResult::Busy
            } else {
                attempt(deps, &schedule, &role, &trigger).await
            };
            conclude(deps, (&schedule, started_at), &trigger, result).await
        }
    }
}

/// The busy window in seconds.
fn window(deps: &RunDeps) -> i64 {
    i64::try_from(deps.timings.busy_window.as_secs()).unwrap_or(i64::MAX)
}

/// Runs the action, again every `busy_retry` while the router is busy and a slot's
/// window lasts, never after the stop.
// NOT cancel-safe: see the action.
async fn attempt(
    deps: &RunDeps,
    schedule: &Schedule,
    role: &Role,
    trigger: &Trigger,
) -> ActionResult {
    let retry = i64::try_from(deps.timings.busy_retry.as_secs()).unwrap_or(i64::MAX);
    loop {
        let call = Call::new(schedule, role, record::actor(&schedule.id), deps.now());
        let result = deps.actions.start(call).await;
        if result != ActionResult::Busy {
            return result;
        }
        let Trigger::Slot(slot) = trigger else {
            return result;
        };
        let next = deps.now().saturating_add(retry);
        if !within_window(*slot, next, window(deps)) {
            return result;
        }
        tokio::select! {
            biased;
            () = deps.stop.cancelled() => return result,
            () = sleep(Duration::from_secs(retry.unsigned_abs())) => {}
        }
    }
}

/// Records, audits and reports how the run of `schedule` begun at `started_at` ended.
// NOT cancel-safe: dropped before the record is written, the run stays `started`.
async fn conclude(
    deps: &Arc<RunDeps>,
    (schedule, started_at): (&Schedule, i64),
    trigger: &Trigger,
    result: ActionResult,
) -> Report {
    let (outcome, job, kind, audited) = match result {
        ActionResult::Done {
            unsaved,
            checksum,
            job,
        } => (
            RunOutcome::Succeeded { unsaved, checksum },
            job,
            done(&schedule.action),
            "success",
        ),
        ActionResult::Failed { code, job } => (
            RunOutcome::Failed {
                code: code.to_owned(),
            },
            job,
            Some(LineKind::Failed {
                code: code.to_owned(),
            }),
            "failed",
        ),
        ActionResult::Skipped { reason, job } => skipped(reason, job),
        ActionResult::Busy => skipped("router_busy", None),
    };
    let (shared, id) = (Arc::clone(deps), schedule.id.clone());
    let (recorded, recorded_job) = (outcome.clone(), job.clone());
    let finished = spawn_blocking(move || {
        record::finish(&shared, (&id, started_at), recorded, recorded_job);
    })
    .await;
    if let Err(error) = finished {
        tracing::error!(target: TARGET, %error, "a run's outcome write did not finish");
    }
    record::audit(
        deps,
        schedule,
        ("schedule.run", audited),
        record::run_params(schedule, trigger, job.as_deref()),
    );
    if let Some(line) = kind {
        deps.report(Line::new(schedule, line));
    }
    Report::Finished(outcome)
}

/// The parts of a skipped run's conclusion.
fn skipped(
    reason: &str,
    job: Option<String>,
) -> (RunOutcome, Option<String>, Option<LineKind>, &'static str) {
    (
        RunOutcome::Skipped {
            reason: reason.to_owned(),
        },
        job,
        Some(LineKind::Skipped {
            reason: reason.to_owned(),
        }),
        "skipped",
    )
}

/// The success line of `action`.
fn done(action: &Action) -> Option<LineKind> {
    match action {
        Action::PolicySwitch { mac: _, policy } => Some(LineKind::PolicySet {
            policy: policy.as_str().to_owned(),
        }),
        Action::Backup => Some(LineKind::BackedUp),
        Action::Reboot => Some(LineKind::Restarted),
        Action::Preset {
            preset_id,
            ack_documentation_tier: _,
        } => Some(LineKind::PresetApplied {
            preset: preset_id.as_str().to_owned(),
        }),
        _ => None,
    }
}
