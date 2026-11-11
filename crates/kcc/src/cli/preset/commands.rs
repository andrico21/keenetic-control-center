//! `kcc preset` dispatch.

use kcc_app::permissions::Permission;
use kcc_i18n::keys;
use kcc_migrate::presets::model::Preset;

use super::{
    args::PresetCommand,
    copy::require_finish,
    finish::finish_run,
    manage::{self, map_preset, scoped_role, store, visible},
    plan::Planned,
    run,
};
use crate::cli::{
    context::{Ctx, Services},
    exit::{Exit, Failure, Outcome},
};

/// Runs a `preset` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: apply and finish change the target under its fail-safe timer.
pub(crate) async fn run(ctx: &Ctx, command: PresetCommand) -> Outcome {
    let services = ctx.services().await?;
    match command {
        PresetCommand::List => manage::list(ctx, &services),
        PresetCommand::Show { id, reveal } => manage::show(ctx, &services, &id, reveal).await,
        PresetCommand::Capture {
            from,
            groups,
            name,
            description,
        } => manage::capture(ctx, &services, &from, (groups, name, description)).await,
        PresetCommand::Delete { id } => manage::delete(ctx, &services, &id).await,
        PresetCommand::Plan { id, options } => {
            let target = ctx.router_id(&services)?;
            let preset = load(ctx, &services, &id)?;
            let planned = Planned::make(ctx, &services, &preset, (&target, &options)).await?;
            let (value, human) = planned.render(ctx, &preset)?;
            ctx.out().emit(&value, &human)
        }
        PresetCommand::Apply {
            id,
            options,
            finish,
        } => {
            require_finish(finish)?;
            let target = ctx.router_id(&services)?;
            ctx.authorize_recovery(&services, &target)
                .await
                .map_err(|_failure| {
                    Failure::message(Exit::Policy, keys::CLI_APPLY_RECOVERY_FORBIDDEN, &[])
                })?;
            let preset = load(ctx, &services, &id)?;
            run::apply(ctx, &services, preset, (&target, &options, finish)).await
        }
        PresetCommand::Finish { run_id, action } => {
            finish_run(ctx, &services, &run_id, action).await
        }
    }
}

/// Loads a stored preset with its protected values for planning and applying.
///
/// # Errors
///
/// Returns the policy refusal, a usage failure for an unknown id, or store failures.
fn load(ctx: &Ctx, services: &Services, id: &str) -> Outcome<Preset> {
    let role = scoped_role(ctx, services, &[Permission::Read, Permission::Migrate])?;
    let preset = store(ctx)?
        .load_for_apply(&role, id)
        .map_err(|error| map_preset(&error, id))?;
    visible(ctx, &preset)?;
    Ok(preset)
}
