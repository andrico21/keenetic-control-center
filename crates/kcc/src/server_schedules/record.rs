//! The synchronous state steps of a run: admission (owner, pause or ledger begin), the
//! ledger's final state, and the audit entries.

use kcc_app::{
    audit::{Actor, ActorKind, AuditEvent, request_id},
    permissions::Role,
    schedules::{
        ledger::{RunError, RunLedger, RunOutcome, Trigger},
        model::{Action, Owner, PauseReason, Schedule, ScheduleState},
        store::{ScheduleStore, SchedulesDocument},
    },
};
use serde_json::{Value, json};

use super::{
    RunDeps, TARGET,
    lines::pause_code,
    owner::{Found, Lookup, permitted},
};

/// What a run found before its action.
#[derive(Debug)]
pub(super) enum Admission {
    /// Nothing to do: the schedule is gone or paused, or the slot already fired.
    Dropped,
    /// The owner cannot run it any more: the schedule was paused for `reason`.
    Paused(Schedule, PauseReason),
    /// The run is recorded as started.
    Begun {
        /// The schedule as read now.
        schedule: Schedule,
        /// The owner's role.
        role: Role,
        /// The run's `started_at`.
        started_at: i64,
    },
}

/// The audit actor of runs of schedule `id`.
pub(super) fn actor(id: &str) -> Actor {
    Actor::new(ActorKind::System, format!("schedule:{id}"))
}

/// Admits a run of schedule `id` for `trigger` at `now`: re-reads the schedule, resolves
/// its owner, and either pauses it or records the run as started.
pub(super) fn admit(deps: &RunDeps, id: &str, trigger: &Trigger, now: i64) -> Admission {
    let Some(schedule) = current(deps, id) else {
        return Admission::Dropped;
    };
    if matches!(trigger, Trigger::Slot(_)) && schedule.state != ScheduleState::Active {
        return Admission::Dropped;
    }
    let role = match authority(deps, &schedule) {
        Ok(Some(role)) => role,
        Ok(None) => return Admission::Dropped,
        Err(reason) => {
            return match ScheduleStore::new(deps.state.clone()).pause_for(id, reason, now) {
                Ok(paused) => Admission::Paused(paused, reason),
                Err(error) => {
                    tracing::warn!(target: TARGET, %error, schedule = id, "a schedule cannot be paused");
                    Admission::Dropped
                }
            };
        }
    };
    match RunLedger::new(deps.state.clone()).begin(id, trigger.clone(), now) {
        Ok(started_at) => Admission::Begun {
            schedule,
            role,
            started_at,
        },
        Err(RunError::AlreadyFired) => Admission::Dropped,
        Err(error) => {
            tracing::warn!(target: TARGET, %error, schedule = id, "a run cannot be recorded");
            Admission::Dropped
        }
    }
}

/// Schedule `id` as stored now.
fn current(deps: &RunDeps, id: &str) -> Option<Schedule> {
    match deps.state.read::<SchedulesDocument>() {
        Ok(document) => document
            .unwrap_or_default()
            .schedules
            .into_iter()
            .find(|schedule| schedule.id == id),
        Err(error) => {
            tracing::warn!(target: TARGET, %error, schedule = id, "schedules cannot be read for a run");
            None
        }
    }
}

/// The role `schedule`'s owner runs it with; `None` when the accounts cannot be read.
///
/// # Errors
///
/// Why the owner cannot run it.
fn authority(deps: &RunDeps, schedule: &Schedule) -> Result<Option<Role>, PauseReason> {
    let lookup = if let Owner::Web { username } = &schedule.owner {
        match deps.accounts.find(username) {
            Ok(found) => found,
            Err(error) => {
                tracing::warn!(target: TARGET, %error, schedule = %schedule.id, "accounts cannot be read for a run");
                return Ok(None);
            }
        }
    } else {
        Lookup::Missing
    };
    let role = Found::new(&deps.roles, &deps.cli).role(schedule, lookup)?;
    permitted(&role, schedule)?;
    Ok(Some(role))
}

/// Records the final state of the run of `id` that began at `started_at`.
pub(super) fn finish(
    deps: &RunDeps,
    (id, started_at): (&str, i64),
    outcome: RunOutcome,
    job: Option<String>,
) {
    let ledger = RunLedger::new(deps.state.clone());
    if let Err(error) = ledger.finish(id, started_at, outcome, job, deps.now()) {
        tracing::warn!(target: TARGET, %error, schedule = id, "a run's outcome cannot be recorded");
    }
}

/// The machine-read name of `action`.
pub(super) const fn action_kind(action: &Action) -> &'static str {
    match action {
        Action::PolicySwitch { mac: _, policy: _ } => "policy_switch",
        Action::Preset {
            preset_id: _,
            ack_documentation_tier: _,
        } => "preset",
        Action::Backup => "backup",
        Action::Reboot => "reboot",
        _ => "other",
    }
}

/// Queues an audit entry by `schedule`'s actor about it.
pub(super) fn audit(
    deps: &RunDeps,
    schedule: &Schedule,
    (action, outcome): (&str, &str),
    params: Value,
) {
    let event = AuditEvent::new(
        u64::try_from(deps.now()).unwrap_or(0),
        actor(&schedule.id),
        action.to_owned(),
    )
    .with_router(schedule.router.clone())
    .with_target(action_kind(&schedule.action).to_owned())
    .with_params(params)
    .with_result(outcome.to_owned(), request_id::next("schedule"));
    if let Err(error) = deps.audit.submit(event) {
        tracing::error!(target: TARGET, %error, schedule = %schedule.id, "a scheduled run's audit entry was not queued");
    }
}

/// The parameters of a `schedule.run` entry.
pub(super) fn run_params(schedule: &Schedule, trigger: &Trigger, job: Option<&str>) -> Value {
    let (slot, requested_by) = match trigger {
        Trigger::Slot(slot) => (Some(*slot), None),
        Trigger::Now { requested_by } => (None, Some(requested_by.as_str())),
        _ => (None, None),
    };
    json!({
        "owner": schedule.owner.to_string(),
        "slot": slot,
        "requested_by": requested_by,
        "job": job,
    })
}

/// The parameters of a `schedule.pause` entry.
pub(super) fn pause_params(schedule: &Schedule, reason: PauseReason) -> Value {
    json!({
        "owner": schedule.owner.to_string(),
        "reason": pause_code(reason),
    })
}
