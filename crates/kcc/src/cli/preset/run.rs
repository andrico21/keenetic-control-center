//! Applying a preset under the router's fail-safe timer and ending the run.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::{audit::Attempt, jobs::JobRunner, permissions::Permission};
use kcc_catalog::Risk;
use kcc_i18n::keys;
use kcc_migrate::{
    apply::{Applier, ApplyError},
    presets::{
        apply::{PresetApplyError, PresetApplyOptions, PresetApplyRequest, request},
        model::Preset,
    },
};
use serde_json::json;

use super::{
    args::{ApplyOptions, Finish},
    finish::{choose, finalize, name},
    plan::Planned,
};
use crate::cli::{
    context::{Ctx, Services},
    exit::{Exit, Failure, Outcome, denied},
    migrate_apply::{apply_failure, reserve, stopped_report},
    secret::confirm,
};

/// Rolls `applier` back, auditing a failed rollback without claiming an unarmed timer is
/// armed; `Ok(true)` when the router accepted the rollback reboot but was not seen back.
///
/// # Errors
///
/// Returns the mapped rollback failure.
// NOT cancel-safe: the rollback sends router requests and may sign in first, and the audit
// writer may append after cancellation.
async fn roll_back(
    ctx: &Ctx,
    services: &Services,
    target: &str,
    applier: &mut Applier,
) -> Outcome<bool> {
    let Err(error) = applier.rollback().await else {
        return Ok(false);
    };
    let failed = Attempt::Failed {
        error: "router",
        fail_safe_armed: error.recovery_armed(),
    };
    ctx.attempt(services, "cli.change", Some(target), failed)
        .await;
    if error == ApplyError::RollbackRestarting {
        Ok(true)
    } else {
        Err(apply_failure(error))
    }
}

/// Maps a preset apply refusal.
fn request_failure(error: PresetApplyError) -> Failure {
    match error {
        PresetApplyError::Forbidden => denied("-"),
        PresetApplyError::PlanNotReady => Failure::message(
            Exit::Validation,
            keys::CLI_PRESET_BLOCKED,
            &[("value", "-")],
        ),
        PresetApplyError::InvalidPlan | _ => Failure::text(Exit::Validation, &error),
    }
}

/// Confirms the apply, and a rollback finish chosen up front as the destructive act it is.
///
/// # Errors
///
/// Returns the policy refusal (exit 10) when a confirmation is missing or wrong.
// NOT cancel-safe: the refusal audit may append after cancellation.
async fn confirm_apply(
    ctx: &Ctx,
    services: &Services,
    target: &str,
    finish: Option<Finish>,
) -> Outcome {
    let confirmation = confirm(ctx.out(), ctx.globals(), Risk::Management, target, false);
    ctx.confirmed(services, target, confirmation).await?;
    if matches!(finish, Some(Finish::Rollback)) {
        let rollback = confirm(ctx.out(), ctx.globals(), Risk::Destructive, target, false);
        ctx.confirmed(services, target, rollback).await?;
    }
    Ok(())
}

/// Plans `preset` onto `target`, prints the plan, asks (or `--yes`), applies, verifies,
/// and ends the run as `finish` says or as chosen on the terminal.
///
/// A failed apply is rolled back. Without a choice the fail-safe timer stays armed.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes the target under its fail-safe timer.
pub(super) async fn apply(
    ctx: &Ctx,
    services: &Services,
    preset: Preset,
    (target, options, finish): (&str, &ApplyOptions, Option<Finish>),
) -> Outcome {
    let planned = Planned::make(ctx, services, &preset, (target, options)).await?;
    let (plan, human) = planned.render(ctx, &preset)?;
    let out = ctx.out();
    out.note(&human);
    planned.ready()?;
    confirm_apply(ctx, services, target, finish).await?;
    let (role, reviewed, inventory) = planned.into_parts();
    let mut input = PresetApplyRequest::new(
        Arc::clone(services.workflow()),
        services.audit_log().clone(),
        ctx.principal().actor(),
        role,
        target.to_owned(),
        preset,
        reviewed,
        inventory,
    );
    if options.keep_wireguard_keys {
        input.options = PresetApplyOptions::default().keep_wireguard_keys();
    }
    let mut protected = request(input).map_err(request_failure)?;
    protected.options.locale = out.locale();
    reserve(ctx, services, &mut protected).await?;
    let runner = JobRunner::open(
        ctx.state().clone(),
        Arc::clone(services.registry()),
        services.audit_log().clone(),
    )
    .await
    .map_err(|error| Failure::text(Exit::Generic, &error))?;
    let (run, done) = Applier::start(&runner, protected)
        .await
        .map_err(apply_failure)?;
    out.note(&out.tr(keys::CLI_PRESET_RUN, &[("name", &run), ("router", target)]));
    let mut applier = done
        .await
        .map_err(|_error| Failure::message(Exit::Generic, keys::CLI_PRESET_JOB_NO_RESULT, &[]))?
        .map_err(apply_failure)?;
    let report = applier.report().clone();
    if let Some(failure) = report.failure {
        let restarting = roll_back(ctx, services, target, &mut applier).await?;
        return Err(stopped_report(failure, report.applied.len(), restarting));
    }
    let action = choose(ctx, finish, (target, &run))?;
    let mut rollback_restarting = false;
    match action {
        Finish::Save => applier.commit().await.map_err(apply_failure)?,
        Finish::Rollback => {
            ctx.authorize_recovery(services, target).await?;
            rollback_restarting = roll_back(ctx, services, target, &mut applier).await?;
        }
        Finish::KeepUnsaved => {
            drop(applier);
            let reached = ctx
                .target_named(
                    services,
                    target.to_owned(),
                    &[Permission::Read, Permission::Migrate],
                )
                .await?;
            drop(finalize(ctx, services, &reached, action).await?);
        }
    }
    let document = json!({
        "router": target,
        "run_id": run,
        "applied": report.applied.len(),
        "failed": report.failed.len(),
        "verified": report.verified,
        "warnings": report.warnings,
        "wireguard_public_keys": report.wireguard_public_keys,
        "finish": name(action),
        "plan": plan,
    });
    let mut text = if rollback_restarting {
        out.tr(keys::MIGRATE_ROLLBACK_SAVED, &[])
    } else {
        report.message(out.locale())
    };
    text.push('\n');
    text.push_str(&out.tr(
        keys::CLI_PRESET_FINISHED,
        &[("name", &run), ("router", target), ("value", name(action))],
    ));
    out.emit(&document, &text)
}
