//! Adding, editing and resuming a schedule: each runs the router's eligibility check
//! with the CLI user's authority, and makes the CLI user the schedule's owner.

use kcc_app::schedules::model::{Action, NewSchedule, Schedule};
use kcc_i18n::{bundle::MessageKey, keys};

use super::{
    audit,
    gate::{checked, confirmed},
    now, owner,
    parse::{self, Field},
    refused, role, store, view,
};
use crate::cli::{
    args_scheduled::{ScheduledAddArgs, ScheduledEditArgs},
    context::{Ctx, Services},
    exit::Outcome,
};

/// Adds a schedule on the selected router.
///
/// # Errors
///
/// Returns usage, policy, check, store or output failures.
// NOT cancel-safe: it reads the router, and the schedule may be stored without its audit
// entry.
pub(super) async fn add(ctx: &Ctx, args: ScheduledAddArgs) -> Outcome {
    let when = parse::when(
        parse::days(&args.days)?,
        parse::at(&args.at)?,
        parse::zone(
            args.tz
                .as_deref()
                .unwrap_or(&ctx.config().schedules.default_timezone),
        )?,
    )?;
    let name = parse::name(&args.name)?;
    let action = parse::action(args.action)?.ok_or(Field::Action)?;
    let services = ctx.services().await?;
    let drafted = NewSchedule::new(name, ctx.router_id(&services)?, when, action);
    let new = approved(ctx, &services, drafted).await?;
    let router = new.router.clone();
    let created = store(ctx)
        .create(&role(ctx)?, new, owner(ctx), now())
        .map_err(|error| refused(error, ("-", &router)))?;
    finish(
        ctx,
        &services,
        (&created, "cli.schedule_add"),
        keys::CLI_SCHEDULED_ADDED,
    )
    .await
}

/// Changes schedule `id`: the options given replace their values, `--router` moves it.
///
/// # Errors
///
/// Returns usage, policy, check, store or output failures.
// NOT cancel-safe: it reads the router, and the schedule may be stored without its audit
// entry.
pub(super) async fn edit(ctx: &Ctx, id: &str, changes: ScheduledEditArgs) -> Outcome {
    let name = changes.name.as_deref().map(parse::name).transpose()?;
    let days = changes.days.as_deref().map(parse::days).transpose()?;
    let time = changes.at.as_deref().map(parse::at).transpose()?;
    let zone = changes.tz.as_deref().map(parse::zone).transpose()?;
    let action = parse::action(changes.action)?;
    let current = store(ctx)
        .get(&role(ctx)?, id)
        .map_err(|error| refused(error, (id, "-")))?;
    let services = ctx.services().await?;
    let was = &current.when;
    let when = parse::when(
        days.unwrap_or_else(|| was.days()),
        time.unwrap_or_else(|| (was.hour(), was.minute())),
        zone.unwrap_or_else(|| was.zone().clone()),
    )?;
    let drafted = NewSchedule::new(
        name.unwrap_or_else(|| current.name.clone()),
        ctx.globals()
            .router()
            .map_or_else(|| current.router.clone(), str::to_owned),
        when,
        action.unwrap_or_else(|| current.action.clone()),
    );
    let edited = approved(ctx, &services, drafted).await?;
    let router = edited.router.clone();
    let updated = store(ctx)
        .update(&role(ctx)?, id, edited, owner(ctx), now())
        .map_err(|error| refused(error, (id, &router)))?;
    finish(
        ctx,
        &services,
        (&updated, "cli.schedule_edit"),
        keys::CLI_SCHEDULED_EDITED,
    )
    .await
}

/// Resumes schedule `id` after the router's eligibility check.
///
/// # Errors
///
/// Returns policy, check, store or output failures.
// NOT cancel-safe: it reads the router, and the schedule may be resumed without its audit
// entry.
pub(super) async fn resume(ctx: &Ctx, id: &str) -> Outcome {
    let role = role(ctx)?;
    let current = store(ctx)
        .get(&role, id)
        .map_err(|error| refused(error, (id, "-")))?;
    let services = ctx.services().await?;
    drop(checked(ctx, &services, (&current.router, &current.action)).await?);
    let resumed = store(ctx)
        .resume(&role, id, owner(ctx), now())
        .map_err(|error| refused(error, (id, &current.router)))?;
    finish(
        ctx,
        &services,
        (&resumed, "cli.schedule_resume"),
        keys::CLI_SCHEDULED_RESUMED,
    )
    .await
}

/// Checks and confirms `new` and adds the preset's source router the check answered.
///
/// # Errors
///
/// Returns policy or check failures.
// NOT cancel-safe: see `checked`.
async fn approved(ctx: &Ctx, services: &Services, new: NewSchedule) -> Outcome<NewSchedule> {
    let action: &Action = &new.action;
    let (_actions, source) = checked(ctx, services, (&new.router, action)).await?;
    confirmed(ctx, services, (&new.router, action)).await?;
    Ok(match source {
        Some(router) => new.with_preset_source(&router),
        None => new,
    })
}

/// Audits `action` about `schedule` and prints it with `key`.
///
/// # Errors
///
/// Returns output failures.
// NOT cancel-safe: the writer may append after cancellation.
async fn finish(
    ctx: &Ctx,
    services: &Services,
    (schedule, action): (&Schedule, &str),
    key: MessageKey,
) -> Outcome {
    audit(ctx, services, action, schedule).await;
    view::changed(ctx, schedule, key)
}
