//! `kcc copy`: a transient preset of the chosen groups, applied onto another router.

use std::io::{self, IsTerminal as _};

use kcc_app::permissions::Permission;
use kcc_i18n::keys;
use kcc_migrate::presets::{
    groups::SettingsGroupEngine,
    model::{CaptureRequest, Preset},
};

use super::{
    args::{CopyCommand, Finish},
    run,
    source::Origin,
};
use crate::cli::{
    context::Ctx,
    exit::{Exit, Failure, Outcome},
};

/// Refuses a run without a terminal and without `--finish`, before anything is read or
/// written: `--yes` never chooses how a run ends.
///
/// # Errors
///
/// Returns the usage failure (exit 2).
pub(super) fn require_finish(finish: Option<Finish>) -> Outcome {
    if finish.is_none() && !io::stdin().is_terminal() {
        return Err(Failure::message(
            Exit::Usage,
            keys::CLI_PRESET_FINISH_REQUIRED,
            &[],
        ));
    }
    Ok(())
}

/// Copies settings groups from `--from` onto `--to`; the copy is never stored. Both
/// routers are authorized before the first router request.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes the target under its fail-safe timer.
pub(crate) async fn run(ctx: &Ctx, args: CopyCommand) -> Outcome {
    require_finish(args.finish)?;
    drop(
        ctx.principal()
            .authorize(&[Permission::Read, Permission::Migrate], &[&args.to])?,
    );
    let services = ctx.services()?;
    let (config, source, _role) = Origin::read(ctx, &services, &args.from).await?.into_parts();
    let selected = args.groups.iter().map(String::as_str).collect::<Vec<_>>();
    let selection = SettingsGroupEngine::embedded()
        .and_then(|engine| engine.select(&config.ast, &selected))
        .map_err(|error| Failure::text(Exit::Usage, &error))?;
    let preset = Preset::captured(
        CaptureRequest::new(
            "copy".to_owned(),
            "copy".to_owned(),
            String::new(),
            args.groups.clone(),
            source,
            ctx.principal().actor().id,
        ),
        selection,
    );
    run::apply(
        ctx,
        &services,
        preset,
        (&args.to, &args.options, args.finish),
    )
    .await
}
