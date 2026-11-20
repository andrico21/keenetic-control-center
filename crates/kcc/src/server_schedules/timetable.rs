//! The timetable: which slots are due, which were missed, which schedules lost their
//! router, and what a server start finds interrupted.

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use core::{future::pending, time::Duration};

use kcc_app::{
    registry::RouterRegistry,
    schedules::{
        ledger::{RunError, RunLedger, RunsDocument, Trigger},
        model::{PauseReason, Schedule, ScheduleState},
        store::{ScheduleStore, SchedulesDocument},
        time::format_local,
    },
};
use tokio::{sync::watch, task::spawn_blocking, time::sleep};

use super::{
    RunDeps, TARGET,
    lines::{Line, LineKind},
    queue::Queues,
    record,
    slots::{Due, due, seconds_until},
};

/// Runs the timetable until the stop, then waits for the runs in progress.
// cancel-safe: dropped, no further slot is queued; runs in progress go on detached.
pub(super) async fn run(
    deps: Arc<RunDeps>,
    registry: Arc<RouterRegistry>,
    reload_requests: watch::Receiver<()>,
) {
    let mut queues = Queues::new(Arc::clone(&deps));
    let mut routers = Some(registry.subscribe_changes());
    let mut reloads = Some(reload_requests);
    start(&deps, &registry).await;
    let mut schedules = active(&deps).await;
    let mut taken = BTreeMap::new();
    let late = i64::try_from(deps.timings.late_limit.as_secs()).unwrap_or(i64::MAX);
    while !deps.stop.is_cancelled() {
        let wake = pass(&deps, &schedules, (&mut taken, late), &mut queues).await;
        let wait = wake.map_or(deps.timings.tick_max, |at| {
            Duration::from_secs(seconds_until(at, deps.now())).min(deps.timings.tick_max)
        });
        tokio::select! {
            biased;
            () = deps.stop.cancelled() => break,
            changed = next_change(&mut reloads) => {
                if changed {
                    schedules = active(&deps).await;
                }
            }
            changed = next_change(&mut routers) => {
                if changed {
                    pause_removed(&deps, &registry).await;
                    schedules = active(&deps).await;
                }
            }
            () = sleep(wait) => {}
        }
    }
    tracing::info!(target: TARGET, event = "stopped", "scheduler stopped; no further run starts");
    queues.close().await;
}

/// Waits for the next change on `receiver`; a closed one is dropped and never resolves
/// again. `false` when it closed.
// cancel-safe: `watch::Receiver::changed` is.
async fn next_change<T>(receiver: &mut Option<watch::Receiver<T>>) -> bool
where
    T: Send + Sync,
{
    let Some(open) = receiver else {
        return pending().await;
    };
    if open.changed().await.is_ok() {
        true
    } else {
        *receiver = None;
        false
    }
}

/// Runs `step` on the blocking pool; `None` when it did not finish.
// cancel-safe: dropped, the step still completes on the blocking pool unobserved.
async fn blocking<T, F>(step: F) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    spawn_blocking(step)
        .await
        .inspect_err(
            |error| tracing::error!(target: TARGET, %error, "a schedule step did not finish"),
        )
        .ok()
}

/// Every schedule.
// cancel-safe: a read.
async fn all(deps: &RunDeps) -> Vec<Schedule> {
    let state = deps.state.clone();
    match blocking(move || state.read::<SchedulesDocument>()).await {
        Some(Ok(document)) => document.unwrap_or_default().schedules,
        Some(Err(error)) => {
            tracing::warn!(target: TARGET, %error, "schedules cannot be read; keeping none");
            Vec::new()
        }
        None => Vec::new(),
    }
}

/// The active schedules.
// cancel-safe: a read.
async fn active(deps: &RunDeps) -> Vec<Schedule> {
    let mut schedules = all(deps).await;
    schedules.retain(|schedule| schedule.state == ScheduleState::Active);
    schedules
}

/// Reports every run a previous server left started, once, as interrupted (it is never
/// run again), then pauses the schedules of routers that are gone.
// NOT cancel-safe: dropped after the ledger marked runs interrupted, their lines are lost.
async fn start(deps: &Arc<RunDeps>, registry: &RouterRegistry) {
    let ledger = RunLedger::new(deps.state.clone());
    let now = deps.now();
    let interrupted = match blocking(move || ledger.interrupt_started(now)).await {
        Some(Ok(found)) => found,
        Some(Err(error)) => {
            tracing::warn!(target: TARGET, %error, "interrupted runs cannot be recorded");
            Vec::new()
        }
        None => Vec::new(),
    };
    if !interrupted.is_empty() {
        let schedules = all(deps).await;
        for (id, _slot) in interrupted {
            if let Some(schedule) = schedules.iter().find(|schedule| schedule.id == id) {
                deps.report(Line::new(schedule, LineKind::Interrupted));
            }
        }
    }
    pause_removed(deps, registry).await;
}

/// Pauses the active schedules of every router no longer registered, and reports each.
// NOT cancel-safe: dropped after a pause, its line and audit entry are lost.
async fn pause_removed(deps: &Arc<RunDeps>, registry: &RouterRegistry) {
    let known = match registry.list() {
        Ok(entries) => entries
            .into_iter()
            .map(|entry| entry.profile.id)
            .collect::<BTreeSet<_>>(),
        Err(error) => {
            tracing::warn!(target: TARGET, %error, "router profiles cannot be listed");
            return;
        }
    };
    let schedules = active(deps).await;
    let gone = schedules
        .iter()
        .map(|schedule| schedule.router.clone())
        .filter(|router| !known.contains(router))
        .collect::<BTreeSet<_>>();
    let now = deps.now();
    for router in gone {
        let store = ScheduleStore::new(deps.state.clone());
        let paused = match blocking(move || store.pause_router(&router, now)).await {
            Some(Ok(ids)) => ids,
            Some(Err(error)) => {
                tracing::warn!(target: TARGET, %error, "schedules of a removed router cannot be paused");
                continue;
            }
            None => continue,
        };
        for schedule in schedules
            .iter()
            .filter(|schedule| paused.contains(&schedule.id))
        {
            let reason = PauseReason::RouterRemoved;
            record::audit(
                deps,
                schedule,
                ("schedule.pause", "success"),
                record::pause_params(schedule, reason),
            );
            deps.report(Line::new(schedule, LineKind::Paused { reason }));
        }
    }
}

/// Queues every slot that has come and skips the missed ones; returns the earliest slot
/// still to come.
// NOT cancel-safe: dropped after a skip was recorded, its line is lost.
async fn pass(
    deps: &Arc<RunDeps>,
    schedules: &[Schedule],
    (taken, late): (&mut BTreeMap<String, i64>, i64),
    workers: &mut Queues,
) -> Option<i64> {
    let store = deps.state.clone();
    let fired = match blocking(move || store.read::<RunsDocument>()).await {
        Some(Ok(document)) => document.unwrap_or_default().schedules,
        Some(Err(error)) => {
            tracing::warn!(target: TARGET, %error, "the run ledger cannot be read; nothing is queued");
            return None;
        }
        None => return None,
    };
    let now = deps.now();
    let mut wake: Option<i64> = None;
    for schedule in schedules {
        let after = [
            fired
                .get(&schedule.id)
                .and_then(|runs| runs.last_fired_slot),
            taken.get(&schedule.id).copied(),
        ]
        .into_iter()
        .flatten()
        .fold(schedule.updated_at, i64::max);
        match due(&schedule.when, after, now, late) {
            Due::Wait(next) => {
                wake = [wake, next].into_iter().flatten().min();
            }
            Due::Run(slot) => {
                let _: Option<i64> = taken.insert(schedule.id.clone(), slot);
                workers.push(&schedule.router, schedule.id.clone(), slot);
            }
            Due::Missed { count, last, then } => {
                let _: Option<i64> = taken.insert(schedule.id.clone(), last);
                skip(deps, schedule, (count, last)).await;
                if let Some(slot) = then {
                    let _: Option<i64> = taken.insert(schedule.id.clone(), slot);
                    workers.push(&schedule.router, schedule.id.clone(), slot);
                }
            }
        }
    }
    wake
}

/// Records `count` missed slots of `schedule` up to `last` as one skip and reports it.
// NOT cancel-safe: dropped after the skip was recorded, its line is lost.
async fn skip(deps: &Arc<RunDeps>, schedule: &Schedule, (count, last): (u32, i64)) {
    let ledger = RunLedger::new(deps.state.clone());
    let (id, now) = (schedule.id.clone(), deps.now());
    match blocking(move || ledger.skip(&id, last, "late", now)).await {
        Some(Ok(())) => {
            record::audit(
                deps,
                schedule,
                ("schedule.run", "skipped"),
                record::run_params(schedule, &Trigger::Slot(last), None),
            );
            let time = format_local(last, schedule.when.zone());
            deps.report(Line::new(schedule, LineKind::Missed { count, time }));
        }
        Some(Err(RunError::AlreadyFired)) | None => {}
        Some(Err(error)) => {
            tracing::warn!(target: TARGET, %error, schedule = %schedule.id, "missed slots cannot be recorded");
        }
    }
}
