//! What `kcc scheduled` shows: the schedules with their next run in the schedule's zone,
//! and one schedule's last runs.

use kcc_app::schedules::{
    ledger::{RunError, RunLedger, RunRecord, RunState},
    model::{Action, PauseReason, Schedule, ScheduleState},
    time::format_local,
};
use kcc_i18n::{bundle::MessageKey, keys};
use serde_json::{Value, json};

use super::{now, refused, role, store};
use crate::{
    cli::{
        context::Ctx,
        exit::{Exit, Failure, Outcome},
        output::Out,
    },
    server_schedules::lines::{pause_code, reason},
};

/// Prints every schedule the role sees.
///
/// # Errors
///
/// Returns store or output failures.
pub(super) fn list(ctx: &Ctx) -> Outcome {
    let schedules = store(ctx)
        .list(&role(ctx)?)
        .map_err(|error| refused(error, ("-", "-")))?;
    let at = now();
    let out = ctx.out();
    let documents = schedules
        .iter()
        .map(|schedule| document(schedule, at))
        .collect::<Outcome<Vec<_>>>()?;
    let rows = schedules
        .iter()
        .map(|schedule| {
            vec![
                schedule.id.clone(),
                schedule.name.as_str().to_owned(),
                schedule.router.clone(),
                when(schedule),
                action(out, &schedule.action),
                state(out, schedule.state),
            ]
        })
        .collect::<Vec<_>>();
    out.table(
        &json!({ "schedules": documents }),
        &[
            keys::CLI_COL_ID,
            keys::CLI_COL_NAME,
            keys::CLI_SCHEDULED_COL_ROUTER,
            keys::CLI_SCHEDULED_COL_WHEN,
            keys::CLI_SCHEDULED_COL_ACTION,
            keys::CLI_SCHEDULED_COL_STATE,
        ],
        &rows,
    )
}

/// Prints schedule `id` with its last runs.
///
/// # Errors
///
/// Returns store, ledger or output failures.
pub(super) fn show(ctx: &Ctx, id: &str) -> Outcome {
    let schedule = store(ctx)
        .get(&role(ctx)?, id)
        .map_err(|error| refused(error, (id, "-")))?;
    let runs = RunLedger::new(ctx.state().clone())
        .runs(id)
        .map_err(|error| match error {
            RunError::State(state) => state.into(),
            RunError::AlreadyFired | RunError::NotFound | _ => Failure::text(Exit::Generic, &error),
        })?;
    let at = now();
    let mut value = document(&schedule, at)?;
    if let Value::Object(fields) = &mut value {
        drop(fields.insert("runs".to_owned(), serde_json::to_value(&runs)?));
    }
    let out = ctx.out();
    out.emit(&value, &detail(out, &schedule, at, runs.last()))
}

/// Prints `schedule` after a change: the document with `--json`, else `key`.
///
/// # Errors
///
/// Returns output failures.
pub(super) fn changed(ctx: &Ctx, schedule: &Schedule, key: MessageKey) -> Outcome {
    let out = ctx.out();
    out.emit(
        &document(schedule, now())?,
        &out.tr(
            key,
            &[("name", schedule.name.as_str()), ("id", &schedule.id)],
        ),
    )
}

/// The `--json` document of `schedule`: as stored, plus its next slot after `now` while
/// it is active.
///
/// # Errors
///
/// Returns a serialization failure.
fn document(schedule: &Schedule, now: i64) -> Outcome<Value> {
    let mut value = serde_json::to_value(schedule)?;
    let next = (schedule.state == ScheduleState::Active)
        .then(|| schedule.when.next_slot_unix(now))
        .flatten();
    if let Value::Object(fields) = &mut value {
        drop(fields.insert("next_slot".to_owned(), json!(next)));
    }
    Ok(value)
}

/// The text of one schedule, its next run and its last run.
fn detail(out: Out, schedule: &Schedule, now: i64, last: Option<&RunRecord>) -> String {
    let zone = schedule.when.zone();
    let mut lines = vec![
        out.tr(
            keys::CLI_SCHEDULED_HEADING,
            &[("name", schedule.name.as_str()), ("id", &schedule.id)],
        ),
        out.tr(keys::CLI_SCHEDULED_ROUTER, &[("router", &schedule.router)]),
        out.tr(keys::CLI_SCHEDULED_WHEN, &[("value", &when(schedule))]),
        out.tr(
            keys::CLI_SCHEDULED_ACTION,
            &[("value", &action(out, &schedule.action))],
        ),
        out.tr(
            keys::CLI_SCHEDULED_OWNER,
            &[("name", &schedule.owner.to_string())],
        ),
        out.tr(
            keys::CLI_SCHEDULED_STATE,
            &[("status", &state(out, schedule.state))],
        ),
    ];
    let next = (schedule.state == ScheduleState::Active)
        .then(|| schedule.when.next_slot_unix(now))
        .flatten();
    if let Some(slot) = next {
        let time = format_local(slot, zone);
        lines.push(out.tr(keys::CLI_SCHEDULED_NEXT, &[("time", &time)]));
    }
    if let Some(run) = last {
        let time = format_local(run.started_at, zone);
        let status = run_state(out, &run.state);
        lines.push(out.tr(
            keys::CLI_SCHEDULED_LAST_RUN,
            &[("time", &time), ("status", &status)],
        ));
    }
    lines.join("\n")
}

/// `mon,wed 03:30 Europe/Berlin`.
fn when(schedule: &Schedule) -> String {
    let when = &schedule.when;
    format!(
        "{} {:02}:{:02} {}",
        when.days().names().collect::<Vec<_>>().join(","),
        when.hour(),
        when.minute(),
        when.zone().as_str()
    )
}

/// The localized summary of `action`.
fn action(out: Out, action: &Action) -> String {
    match action {
        Action::PolicySwitch { mac, policy } => out.tr(
            keys::CLI_SCHEDULED_ACTION_POLICY,
            &[("policy", policy.as_str()), ("value", mac.as_str())],
        ),
        Action::Preset {
            preset_id,
            ack_documentation_tier: _,
        } => out.tr(
            keys::CLI_SCHEDULED_ACTION_PRESET,
            &[("preset", preset_id.as_str())],
        ),
        Action::Backup => out.tr(keys::CLI_SCHEDULED_ACTION_BACKUP, &[]),
        Action::Reboot | _ => out.tr(keys::CLI_SCHEDULED_ACTION_REBOOT, &[]),
    }
}

/// The localized state.
fn state(out: Out, state: ScheduleState) -> String {
    let ScheduleState::Paused { reason: why, at: _ } = state else {
        return out.tr(keys::CLI_SCHEDULED_STATE_ACTIVE, &[]);
    };
    let text = if why == PauseReason::Manual {
        out.tr(keys::CLI_SCHEDULED_REASON_MANUAL, &[])
    } else {
        reason(out.locale(), pause_code(why))
    };
    out.tr(keys::CLI_SCHEDULED_STATE_PAUSED, &[("reason", &text)])
}

/// The localized state of a run.
fn run_state(out: Out, state: &RunState) -> String {
    match state {
        RunState::Succeeded {
            unsaved: _,
            checksum: _,
        } => out.tr(keys::CLI_SCHEDULED_RUN_SUCCEEDED, &[]),
        RunState::Failed { code } => out.tr(
            keys::CLI_SCHEDULED_RUN_FAILED,
            &[("reason", &reason(out.locale(), code))],
        ),
        RunState::Skipped { reason: code } => out.tr(
            keys::CLI_SCHEDULED_RUN_SKIPPED,
            &[("reason", &reason(out.locale(), code))],
        ),
        RunState::Started => out.tr(keys::CLI_SCHEDULED_RUN_STARTED, &[]),
        RunState::Interrupted | _ => out.tr(keys::CLI_SCHEDULED_RUN_INTERRUPTED, &[]),
    }
}
