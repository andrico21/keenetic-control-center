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
    migrate_apply::apply_failure,
    secret::confirm,
};

/// Audits one failed preset rollback without claiming an unarmed timer is armed.
// NOT cancel-safe: the audit writer may append after cancellation.
async fn audit_rollback_failure(ctx: &Ctx, services: &Services, target: &str, error: ApplyError) {
    let failed = Attempt::Failed {
        error: "router",
        fail_safe_armed: error.recovery_armed(),
    };
    ctx.attempt(services, "cli.change", Some(target), failed)
        .await;
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
    let confirmation = confirm(out, ctx.globals(), Risk::Management, target, false);
    ctx.confirmed(services, target, confirmation).await?;
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
        .map_err(|_error| Failure::text(Exit::Generic, "the preset job ended without a result"))?
        .map_err(apply_failure)?;
    let report = applier.report().clone();
    if let Some(failure) = report.failure {
        if let Err(error) = applier.rollback().await {
            audit_rollback_failure(ctx, services, target, error).await;
            if error != ApplyError::RollbackRestarting {
                return Err(apply_failure(error));
            }
        }
        return Err(apply_failure(failure));
    }
    let action = choose(ctx, finish, (target, &run))?;
    let mut rollback_restarting = false;
    match action {
        Finish::Save => applier.commit().await.map_err(apply_failure)?,
        Finish::Rollback => {
            ctx.authorize_recovery(services, target).await?;
            if let Err(error) = applier.rollback().await {
                audit_rollback_failure(ctx, services, target, error).await;
                if error != ApplyError::RollbackRestarting {
                    return Err(apply_failure(error));
                }
                rollback_restarting = true;
            }
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
