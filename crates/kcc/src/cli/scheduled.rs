//! `kcc scheduled`: weekly scheduled actions without the Web UI.
//!
//! It edits `schedules.json` through the same store and the same checks against the
//! router as the Web page; a running `kcc serve` picks the edits up within its state
//! watch. `run-now` runs one schedule in this process through the server's run path, as
//! the schedule's owner: it sends no Telegram message and does not try a busy router
//! again. Nothing here starts the scheduler or saves a router's configuration.

mod gate;
mod parse;
mod run_now;
mod view;
mod write;

use kcc_app::{
    accounts::{Clock as _, SystemClock},
    permissions::{Permission, Role},
    schedules::{
        model::{Action, Owner, Schedule},
        store::{MAX_PER_ROUTER, MAX_TOTAL, ScheduleError, ScheduleStore},
    },
};
use kcc_i18n::{bundle::MessageKey, keys};
use serde_json::json;

use super::{
    args_scheduled::ScheduledCommand,
    context::{Ctx, Services},
    exit::{Exit, Failure, Outcome, denied},
};

/// Runs a `scheduled` command; every one needs `manage_schedules`.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes local state, may change a router and appends audit entries.
pub(crate) async fn run(ctx: &Ctx, command: ScheduledCommand) -> Outcome {
    ctx.principal().require(Permission::ManageSchedules)?;
    match command {
        ScheduledCommand::List => view::list(ctx),
        ScheduledCommand::Show { id } => view::show(ctx, &id),
        ScheduledCommand::Add(args) => write::add(ctx, args).await,
        ScheduledCommand::Edit { id, changes } => write::edit(ctx, &id, changes).await,
        ScheduledCommand::Pause { id } => pause(ctx, &id).await,
        ScheduledCommand::Resume { id } => write::resume(ctx, &id).await,
        ScheduledCommand::Delete { id } => delete(ctx, &id).await,
        ScheduledCommand::RunNow { id } => run_now::run(ctx, &id).await,
    }
}

/// Pauses schedule `id` by hand.
///
/// # Errors
///
/// Returns store or output failures.
// NOT cancel-safe: the schedule may be paused without its audit entry.
async fn pause(ctx: &Ctx, id: &str) -> Outcome {
    let services = ctx.services().await?;
    let role = role(ctx)?;
    let store = store(ctx);
    let schedule = store
        .get(&role, id)
        .map_err(|error| refused(error, (id, "-")))?;
    let paused = store
        .pause(&role, id, now())
        .map_err(|error| refused(error, (id, &schedule.router)))?;
    audit(ctx, &services, "cli.schedule_pause", &paused).await;
    view::changed(ctx, &paused, keys::CLI_SCHEDULED_PAUSED)
}

/// Deletes schedule `id` and its run history.
///
/// # Errors
///
/// Returns store or output failures.
// NOT cancel-safe: the schedule may be deleted without its audit entry.
async fn delete(ctx: &Ctx, id: &str) -> Outcome {
    let services = ctx.services().await?;
    let role = role(ctx)?;
    let store = store(ctx);
    let schedule = store
        .get(&role, id)
        .map_err(|error| refused(error, (id, "-")))?;
    store
        .delete(&role, id)
        .map_err(|error| refused(error, (id, &schedule.router)))?;
    audit(ctx, &services, "cli.schedule_delete", &schedule).await;
    let out = ctx.out();
    out.emit(
        &json!({ "id": id, "deleted": true }),
        &out.tr(keys::CLI_SCHEDULED_DELETED, &[("id", id)]),
    )
}

/// The schedules of this state directory.
fn store(ctx: &Ctx) -> ScheduleStore {
    ScheduleStore::new(ctx.state().clone())
}

/// The CLI user as a schedule's owner.
fn owner(ctx: &Ctx) -> Owner {
    Owner::Cli {
        os_user: ctx.principal().account_name().to_owned(),
    }
}

/// The CLI user's authority over schedules: the role within both router scopes.
///
/// # Errors
///
/// Returns the policy refusal when the scopes share no router.
fn role(ctx: &Ctx) -> Outcome<Role> {
    ctx.principal().authority()
}

/// The wall clock, Unix seconds.
fn now() -> i64 {
    i64::try_from(SystemClock::default().unix_seconds()).unwrap_or(i64::MAX)
}

/// The machine-read name of `action`, as `schedule.run` entries name it.
const fn kind(action: &Action) -> &'static str {
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

/// Appends `action`'s audit entry about `schedule`: its id, action kind and router;
/// never a client or a policy.
// NOT cancel-safe: the writer may append after cancellation.
async fn audit(ctx: &Ctx, services: &Services, action: &str, schedule: &Schedule) {
    let params = json!({
        "id": schedule.id,
        "action": kind(&schedule.action),
        "router": schedule.router,
    });
    ctx.audit(services, action, Some(&schedule.router), params, "success")
        .await;
}

/// The failure of a refused store operation on schedule `id` of `router`.
fn refused(error: ScheduleError, (id, router): (&str, &str)) -> Failure {
    let limit = |key: MessageKey, max: usize| {
        Failure::message(Exit::Validation, key, &[("max", &max.to_string())])
    };
    match error {
        ScheduleError::Forbidden => denied(router),
        ScheduleError::NotFound => {
            Failure::message(Exit::Usage, keys::CLI_SCHEDULED_UNKNOWN, &[("id", id)])
        }
        ScheduleError::DuplicateName => Failure::message(
            Exit::Conflict,
            keys::CLI_SCHEDULED_NAME_TAKEN,
            &[("router", router)],
        ),
        ScheduleError::RouterLimit => limit(keys::CLI_SCHEDULED_LIMIT_ROUTER, MAX_PER_ROUTER),
        ScheduleError::TotalLimit => limit(keys::CLI_SCHEDULED_LIMIT_TOTAL, MAX_TOTAL),
        ScheduleError::State(state) => state.into(),
        ScheduleError::IdUnavailable | _ => Failure::text(Exit::Generic, &error),
    }
}
