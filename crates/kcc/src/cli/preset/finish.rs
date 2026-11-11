//! Ending a preset run: keep the changes unsaved, save them, or roll back.

extern crate alloc;

use alloc::sync::Arc;
use std::io::{self, BufRead as _, IsTerminal as _, Write as _};

use kcc_app::{jobs::JobRunner, permissions::Permission};
use kcc_catalog::Risk;
use kcc_domain::configuration::{self, SafetyMode, SafetyNet, recovery};
use kcc_i18n::keys;
use serde_json::{Value, json};

use super::args::Finish;
use crate::cli::{
    change::{Gate, run as run_change, safety_mode},
    context::{Ctx, Services, Target},
    exit::{Exit, Failure, Outcome},
};

/// The stable name of a finish action.
pub(super) const fn name(action: Finish) -> &'static str {
    match action {
        Finish::KeepUnsaved => "keep-unsaved",
        Finish::Save => "save",
        Finish::Rollback => "rollback",
    }
}

/// The finish action named on the command line, else the one chosen on the terminal.
///
/// # Errors
///
/// Returns the usage failure when neither is available (the timer stays armed).
pub(super) fn choose(
    ctx: &Ctx,
    chosen: Option<Finish>,
    (router, run): (&str, &str),
) -> Outcome<Finish> {
    if let Some(action) = chosen {
        return Ok(action);
    }
    let stdin = io::stdin();
    let left = || Failure::message(Exit::Usage, keys::CLI_PRESET_FINISH_LEFT, &[("value", run)]);
    if !stdin.is_terminal() {
        return Err(left());
    }
    let question = ctx
        .out()
        .tr(keys::CLI_PRESET_FINISH_ASK, &[("router", router)]);
    loop {
        let mut stderr = io::stderr().lock();
        write!(stderr, "{question} ")?;
        stderr.flush()?;
        drop(stderr);
        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            return Err(left());
        }
        match line.trim() {
            "keep-unsaved" => return Ok(Finish::KeepUnsaved),
            "save" => return Ok(Finish::Save),
            "rollback" => return Ok(Finish::Rollback),
            _ => {}
        }
    }
}

/// Ends the run on `target` through a fresh change set (the router's fail-safe timer
/// still guards it).
///
/// # Errors
///
/// Returns the policy refusal, a missing confirmation, or the workflow failure.
// NOT cancel-safe: the router may save, disarm or roll back before cancellation.
pub(super) async fn finalize(
    ctx: &Ctx,
    services: &Services,
    target: &Target,
    action: Finish,
) -> Outcome<Value> {
    let mode = safety_mode(target.info());
    if matches!(action, Finish::KeepUnsaved)
        || matches!(action, Finish::Save) && mode == SafetyMode::ScheduledReboot
    {
        ctx.authorize_recovery(services, target.id()).await?;
    }
    let gate = match action {
        Finish::KeepUnsaved => Gate::new(Risk::Write, Permission::Write, false),
        Finish::Save => Gate::new(Risk::Write, Permission::Save, false),
        Finish::Rollback => Gate::new(Risk::Destructive, Permission::Destructive, false),
    };
    run_change(ctx, services, target, gate, async |changes, router| {
        match (action, mode) {
            (Finish::KeepUnsaved, _) => {
                let disarm = SafetyNet::disarm(changes, router, mode)
                    .await
                    .map_err(Failure::from);
                recovery::finish(Ok(()), disarm).map_err(Failure::recovery)?;
            }
            (Finish::Save, SafetyMode::Router) => SafetyNet::commit(changes).await?,
            (Finish::Save, SafetyMode::ScheduledReboot | _) => {
                configuration::save(changes).await?;
                ctx.out().note(&ctx.out().tr(keys::CLI_SAVED, &[]));
                let disarm = SafetyNet::disarm(changes, router, mode)
                    .await
                    .map_err(Failure::from);
                recovery::finish(Ok(()), disarm).map_err(Failure::recovery)?;
            }
            (Finish::Rollback, _) => drop(SafetyNet::rollback(changes, router).await?),
        }
        Ok(json!({ "router": target.id(), "finish": name(action) }))
    })
    .await
}

/// `preset finish <run-id> <action>`: ends a run started by another process.
///
/// # Errors
///
/// Returns usage (unknown run), policy, confirmation or workflow failures.
// NOT cancel-safe: see `finalize`.
pub(super) async fn finish_run(
    ctx: &Ctx,
    services: &Services,
    run: &str,
    action: Finish,
) -> Outcome {
    let runner = JobRunner::open(ctx.state().clone(), Arc::clone(services.registry()))
        .await
        .map_err(|error| Failure::text(Exit::Generic, &error))?;
    let not_run = || Failure::message(Exit::Usage, keys::CLI_PRESET_NOT_RUN, &[("name", run)]);
    let record = runner.get(run).map_err(|_error| not_run())?;
    let router = record
        .router
        .filter(|_router| record.kind == "migration")
        .ok_or_else(not_run)?;
    let target = ctx
        .target_named(services, router, &[Permission::Read, Permission::Migrate])
        .await?;
    let document = finalize(ctx, services, &target, action).await?;
    let out = ctx.out();
    out.emit(
        &document,
        &out.tr(
            keys::CLI_PRESET_FINISHED,
            &[
                ("name", run),
                ("router", target.id()),
                ("value", name(action)),
            ],
        ),
    )
}
