//! Migration commands: inventory, plan, apply, finish and report.

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use kcc_domain::{
    configuration::{SafetyMode, SafetyNet, recovery},
    system,
};
use kcc_i18n::keys;
use kcc_migrate::{
    inventory::{InventoryClient, TargetInventory},
    planner::MigrationPlan,
    report::MigrationReport,
};
use kcc_rci::capabilities::SupportTier;
use serde_json::{Value, json};

use super::{
    args_migrate::{FinishStep, MigrateCommand, PlanInput, ReportFormat},
    change::{Gate, applied, run as run_change, safety_mode},
    context::{Ctx, Services},
    exit::{Exit, Failure, Outcome},
    files, migrate_apply,
    migrate_plan::Planned,
};

/// Runs a `migrate` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: apply and finish change the target under its fail-safe timer.
pub(crate) async fn run(ctx: &Ctx, command: MigrateCommand) -> Outcome {
    let services = ctx.services().await?;
    let out = ctx.out();
    match command {
        MigrateCommand::Inventory => inventory(ctx, &services).await,
        MigrateCommand::Plan { input, out: path } => {
            let planned = Planned::make(ctx, &services, &input).await?;
            let mut document = serde_json::to_value(planned.plan())?;
            if let Value::Object(fields) = &mut document {
                drop(fields.insert(
                    "target".to_owned(),
                    Value::String(planned.target().to_owned()),
                ));
                drop(fields.insert(
                    "ack_documentation_tier".to_owned(),
                    Value::Bool(input.ack_documentation_tier),
                ));
            }
            files::write_private(
                &path,
                serde_json::to_string_pretty(&document)?.as_bytes(),
                false,
            )?;
            note_tier(ctx, &planned, &input);
            let count = line_count(planned.plan()).to_string();
            let shown = path.display().to_string();
            out.emit(
                &json!({ "plan_id": planned.plan().plan_id, "path": shown, "lines": line_count(planned.plan()) }),
                &out.tr(keys::CLI_PLAN_WRITTEN, &[("path", &shown), ("count", &count)]),
            )
        }
        MigrateCommand::Apply {
            input,
            plan,
            finish,
            safety_seconds,
            report,
        } => {
            let target = ctx.router_id(&services)?;
            ctx.authorize_apply(&services, &target).await?;
            migrate_apply::apply(
                ctx,
                &services,
                &input,
                &plan,
                (finish, safety_seconds, report.as_deref()),
            )
            .await
        }
        MigrateCommand::Finish { action } => finish(ctx, &services, action).await,
        MigrateCommand::Report {
            input,
            format,
            out: path,
        } => {
            let planned = Planned::make(ctx, &services, &input).await?;
            let report = MigrationReport::from_plan(planned.plan(), out.locale());
            let text = match format {
                ReportFormat::Markdown => report.to_markdown(),
                ReportFormat::Json => report
                    .to_json()
                    .map_err(|error| Failure::text(Exit::Generic, &error))?,
                ReportFormat::Html => report
                    .to_html()
                    .map_err(|error| Failure::text(Exit::Generic, &error))?,
            };
            match path {
                Some(file) => {
                    files::write_private(&file, text.as_bytes(), false)?;
                    out.emit(
                        &json!({ "path": file }),
                        &out.tr(
                            keys::CLI_CONFIG_WRITTEN,
                            &[("path", &file.display().to_string())],
                        ),
                    )
                }
                None => out.emit(&json!({ "report": text }), &text),
            }
        }
    }
}

/// Prints the target inventory.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// cancel-safe: reads only.
async fn inventory(ctx: &Ctx, services: &Services) -> Outcome {
    let target = ctx.router_id(services)?;
    let role = ctx
        .principal()
        .authorize(&[Permission::Read, Permission::Migrate], &[&target])?;
    let client = services.registry().bootstrap_client(&role, &target).await?;
    let found = TargetInventory::collect(&InventoryClient::from_client(&client), None)
        .await
        .map_err(|error| Failure::text(Exit::Router, &error))?;
    let document = json!({
        "router": target,
        "model": found.info.version.model,
        "hardware_id": found.info.version.hw_id,
        "firmware": found.info.firmware.map(|version| version.to_string()),
        "management_interface": found.management_interface,
        "fail_safe_available": found.fail_safe_available,
        "ports": found.ports.iter().map(|port| json!({ "id": port.id, "label": port.label })).collect::<Vec<_>>(),
        "radios": found.radios.iter().map(|radio| radio.id.clone()).collect::<Vec<_>>(),
        "interfaces": found.interfaces.iter().map(|interface| json!({ "name": interface.name, "kind": interface.kind })).collect::<Vec<_>>(),
        "installed_components": found.installed_components,
        "usb_modems": found.usb_modems,
    });
    ctx.out()
        .emit(&document, &serde_json::to_string_pretty(&document)?)
}

/// Commits or rolls back a kept migration through the router's fail-safe timer.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the commit or rollback may complete before cancellation.
async fn finish(ctx: &Ctx, services: &Services, action: FinishStep) -> Outcome {
    let target = ctx.target(services, &[Permission::Migrate]).await?;
    let mode = safety_mode(target.info());
    if matches!(action, FinishStep::Commit) && mode == SafetyMode::ScheduledReboot {
        ctx.authorize_recovery(services, target.id()).await?;
    }
    let (gate, outcome) = match action {
        FinishStep::Commit => (
            Gate::new(Risk::Write, Permission::Save, false),
            keys::CLI_MIGRATE_COMMITTED,
        ),
        FinishStep::Rollback => (
            Gate::new(Risk::Destructive, Permission::Destructive, false),
            if mode == SafetyMode::ScheduledReboot {
                keys::MIGRATE_ROLLBACK_SAVED
            } else {
                keys::CLI_MIGRATE_ROLLED_BACK
            },
        ),
    };
    let mut saved = false;
    let document = run_change(ctx, services, &target, gate, async |changes, router| {
        match (action, mode) {
            (FinishStep::Commit, _) => {
                ctx.finish_saved(changes, router, mode)
                    .await
                    .map_err(|error| {
                        saved = error.applied();
                        Failure::recovery(error)
                    })?;
            }
            (FinishStep::Rollback, SafetyMode::Router) => {
                drop(
                    SafetyNet::rollback(changes, router)
                        .await
                        .map_err(|error| {
                            Failure::recovery(recovery::Failure::armed(Failure::from(error)))
                        })?,
                );
            }
            (FinishStep::Rollback, SafetyMode::ScheduledReboot | _) => {
                drop(system::reboot(changes, router).await.map_err(|error| {
                    Failure::recovery(recovery::Failure::armed(Failure::from(error)))
                })?);
            }
        }
        Ok(applied(matches!(action, FinishStep::Rollback)))
    })
    .await
    .map_err(|error| {
        if saved {
            Failure::headline_only(Exit::Router, keys::FINISH_SAVED_ARMED)
        } else {
            error
        }
    })?;
    let out = ctx.out();
    out.emit(&document, &out.tr(outcome, &[]))
}

/// Notes a documentation-based target the plan was not acknowledged for.
fn note_tier(ctx: &Ctx, planned: &Planned, input: &PlanInput) {
    if planned.inventory().info.support_tier() == SupportTier::DocumentationBased
        && !input.ack_documentation_tier
    {
        ctx.out().note(&ctx.out().tr(keys::MIGRATE_APPLY_TIER, &[]));
    }
}

/// Lines the plan sends.
const fn line_count(plan: &MigrationPlan) -> usize {
    plan.phases
        .additive
        .len()
        .saturating_add(plan.phases.prune.len())
        .saturating_add(plan.phases.management.len())
}
