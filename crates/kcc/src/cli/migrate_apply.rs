//! Applying a reviewed migration plan.

extern crate alloc;

use alloc::sync::Arc;
use std::path::Path;

use kcc_app::jobs::JobRunner;
use kcc_i18n::keys;
use kcc_migrate::apply::{Applier, ApplyError, ApplyRequest};
use serde_json::{Value, json};
use tokio::fs::read;

use super::{
    args_migrate::{FinishAction, PlanInput},
    context::{Ctx, Services},
    exit::{Exit, Failure, Outcome},
    files,
    migrate_plan::Planned,
};

mod migrate_apply_finish;

/// Re-plans, checks the plan file, applies and finishes as asked.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes the target under its fail-safe timer.
pub(crate) async fn apply(
    ctx: &Ctx,
    services: &Services,
    input: &PlanInput,
    plan_file: &Path,
    (finish, safety_seconds, report_file): (FinishAction, u64, Option<&Path>),
) -> Outcome {
    let reviewed: Value = serde_json::from_slice(&read(plan_file).await?)?;
    let planned = Planned::make(ctx, services, input).await?;
    if reviewed.get("plan_id").and_then(Value::as_str) != Some(planned.plan().plan_id.as_str()) {
        return Err(Failure::message(
            Exit::Conflict,
            keys::CLI_PLAN_CHANGED,
            &[],
        ));
    }
    let (target, role, plan, source, management_password) = planned.into_parts();
    let mut request = ApplyRequest::new(
        Arc::clone(services.workflow()),
        services.audit_log().clone(),
        ctx.principal().actor(),
        role,
        target.clone(),
        plan,
        source,
    );
    request.options.ack_documentation_tier = input.ack_documentation_tier;
    request.options.management_password = management_password;
    request.options.safety_seconds = safety_seconds;
    request.options.locale = ctx.out().locale();
    let runner = JobRunner::open(ctx.state().clone(), Arc::clone(services.registry()))
        .await
        .map_err(|error| Failure::text(Exit::Generic, &error))?;
    let (_job, done) = Applier::start(&runner, request)
        .await
        .map_err(apply_failure)?;
    let mut applier = done
        .await
        .map_err(|_error| Failure::text(Exit::Generic, "the migration job ended without a result"))?
        .map_err(apply_failure)?;
    let report = applier.report().clone();
    let (action, rollback_restarting) =
        migrate_apply_finish::finish(ctx, services, &target, &mut applier, finish, report.failure)
            .await?;
    drop(applier);
    if let Some(path) = report_file {
        files::write_private(
            path,
            serde_json::to_string_pretty(&report)?.as_bytes(),
            false,
        )?;
    }
    let out = ctx.out();
    let document = json!({
        "router": target,
        "applied": report.applied.len(),
        "failed": report.failed.len(),
        "verified": report.verified,
        "finish": action,
        "failure": report.failure,
    });
    let mut human = if rollback_restarting {
        out.tr(keys::MIGRATE_ROLLBACK_SAVED, &[])
    } else if action == "rollback" && report.failure == Some(ApplyError::Verification) {
        out.tr(keys::MIGRATE_APPLY_RESTORED, &[])
    } else {
        report.message(out.locale())
    };
    if action == "keep" {
        human.push('\n');
        human.push_str(&out.tr(keys::CLI_MIGRATE_KEPT, &[]));
    }
    out.emit(&document, &human)?;
    report.failure.map_or(Ok(()), |failure| {
        if action == "rollback" && failure == ApplyError::Verification {
            Err(Failure::headline_only(
                Exit::Router,
                keys::MIGRATE_APPLY_RESTORED,
            ))
        } else {
            Err(apply_failure(failure))
        }
    })
}

/// Maps a migration failure to its exit code and localized message.
pub(crate) fn apply_failure(error: ApplyError) -> Failure {
    match error {
        ApplyError::SavedDisarmFailed => {
            return Failure::headline_only(Exit::Router, keys::FINISH_SAVED_ARMED);
        }
        ApplyError::DisarmFailed => {
            return Failure::headline_only(Exit::Router, keys::MANAGEMENT_DISARM_FAILED);
        }
        ApplyError::FinishFailed => {
            return Failure::headline_only(Exit::Router, keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED);
        }
        ApplyError::CommittedSaveFailed => {
            return Failure::headline_only(Exit::Router, keys::MIGRATE_COMMITTED_NOT_SAVED);
        }
        ApplyError::RollbackRestarting => {
            return Failure::headline_only(Exit::Router, keys::MIGRATE_ROLLBACK_SAVED);
        }
        ApplyError::UnverifiedFirmwareTier
        | ApplyError::AgreementRequired
        | ApplyError::RolledBackByRouter
        | ApplyError::Firmware
        | ApplyError::Drift
        | ApplyError::ReplanRequired
        | ApplyError::Validation
        | ApplyError::PasswordRequired
        | ApplyError::SameRouter
        | ApplyError::HardwareMismatch
        | ApplyError::Source
        | ApplyError::Unreachable
        | ApplyError::Stopped
        | ApplyError::Verification
        | ApplyError::Workflow
        | ApplyError::Cancelled
        | ApplyError::Job
        | ApplyError::JobStart
        | _ => {}
    }
    let (exit, key) = match error {
        ApplyError::UnverifiedFirmwareTier => (Exit::Policy, keys::MIGRATE_APPLY_TIER),
        ApplyError::AgreementRequired => (Exit::Policy, keys::MIGRATE_APPLY_AGREEMENT),
        ApplyError::RolledBackByRouter => (Exit::Router, keys::MIGRATE_APPLY_ROUTER_ROLLBACK),
        ApplyError::Firmware => (Exit::Policy, keys::MIGRATE_APPLY_FAILED),
        ApplyError::Drift | ApplyError::ReplanRequired => (Exit::Conflict, keys::CLI_PLAN_CHANGED),
        ApplyError::Validation
        | ApplyError::PasswordRequired
        | ApplyError::SameRouter
        | ApplyError::HardwareMismatch => (Exit::Validation, keys::MIGRATE_APPLY_FAILED),
        ApplyError::Source
        | ApplyError::Unreachable
        | ApplyError::Stopped
        | ApplyError::Verification => (Exit::Router, keys::MIGRATE_APPLY_FAILED),
        ApplyError::JobStart => (Exit::Generic, keys::MIGRATE_JOB_START_FAILED),
        ApplyError::Workflow | ApplyError::Cancelled | ApplyError::Job | _ => {
            (Exit::Generic, keys::MIGRATE_APPLY_FAILED)
        }
    };
    Failure::message(exit, key, &[])
}
