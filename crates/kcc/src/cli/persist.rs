//! Configuration persistence, the fail-safe timer, and backups.

use core::str;
use std::path::Path;

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use kcc_domain::configuration::{
    self, SafetyMode, SafetyNet, TIMER_RANGE,
    close::{Close, Closed, close},
};
use kcc_i18n::keys;
use kcc_rci::ConfigKind;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};

use super::{
    args_fleet::{BackupCommand, FailsafeAction},
    change::{Gate, applied, recovery_mode, run as run_change},
    closing::reported,
    context::{Ctx, Services},
    exit::{Exit, Failure, Outcome},
    files,
    line_diff::between,
    redact::{Lines, redacted_copy},
    secret::confirm,
};

/// Shows unsaved changes, the last changing agent and the fail-safe timer.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
pub(crate) async fn config_state(ctx: &Ctx) -> Outcome {
    let services = ctx.services().await?;
    let out = ctx.out();
    let target = ctx.target(&services, &[Permission::Read]).await?;
    let state = configuration::read_last_change(target.router()).await?;
    let document = serde_json::to_value(&state)?;
    let fail_safe = state
        .fail_safe
        .as_ref()
        .and_then(|timer| timer.active)
        .unwrap_or(false);
    let human = [
        out.tr(
            keys::CLI_CONFIG_UNSAVED,
            &[(
                "value",
                yes_no(out, state.unsaved.unwrap_or(false)).as_str(),
            )],
        ),
        out.tr(
            keys::CLI_CONFIG_AGENT,
            &[("value", state.agent.as_deref().unwrap_or("-"))],
        ),
        out.tr(
            keys::CLI_CONFIG_FAILSAFE,
            &[("value", yes_no(out, fail_safe).as_str())],
        ),
    ]
    .join("\n");
    out.emit(&document, &human)
}

/// Saves the running configuration.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the save may complete before cancellation.
pub(crate) async fn config_save(ctx: &Ctx) -> Outcome {
    let services = ctx.services().await?;
    let out = ctx.out();
    let target = ctx.target(&services, &[Permission::Save]).await?;
    let gate = Gate::new(Risk::Write, Permission::Save, false);
    let document = run_change(ctx, &services, &target, gate, async |changes, _router| {
        changes.save().await?;
        Ok(json!({ "saved": true }))
    })
    .await?;
    out.emit(&document, &out.tr(keys::CLI_SAVED, &[]))
}

/// Runs a fail-safe timer action.
///
/// # Errors
/// Returns validation, policy, workflow, or router failures.
// NOT cancel-safe: timer actions may complete before cancellation.
pub(crate) async fn failsafe(ctx: &Ctx, action: FailsafeAction, seconds: u64) -> Outcome {
    let services = &ctx.services().await?;
    let (permission, risk) = match action {
        FailsafeAction::Arm | FailsafeAction::Rollback => {
            (Permission::Destructive, Risk::Destructive)
        }
        FailsafeAction::Commit => (Permission::Save, Risk::Write),
    };
    if !TIMER_RANGE.contains(&seconds) {
        return Err(Failure::message(
            Exit::Usage,
            keys::CLI_FAILSAFE_SECONDS_RANGE,
            &[],
        ));
    }
    let target = ctx.target(services, &[permission]).await?;
    let mode = recovery_mode(&target).await?;
    if matches!(action, FailsafeAction::Commit) && mode == SafetyMode::ScheduledReboot {
        ctx.authorize_recovery(services, target.id()).await?;
    }
    let outcome = match (action, mode) {
        (FailsafeAction::Arm, _) => keys::CLI_FAILSAFE_RUNNING,
        (FailsafeAction::Commit, _) => keys::CLI_FAILSAFE_COMMITTED,
        (FailsafeAction::Rollback, SafetyMode::ScheduledReboot) => {
            keys::FAILSAFE_ROLLBACK_REBOOTING
        }
        (FailsafeAction::Rollback, SafetyMode::Router | _) => keys::CLI_FAILSAFE_ROLLED_BACK,
    };
    let document = run_change(
        ctx,
        services,
        &target,
        Gate::new(risk, permission, false),
        async |changes, router| {
            let step = match action {
                FailsafeAction::Arm => {
                    drop(
                        SafetyNet::arm(changes, router, mode, seconds, Permission::Destructive)
                            .await?,
                    );
                    return Ok(applied(true));
                }
                FailsafeAction::Commit => Close::Save,
                FailsafeAction::Rollback => Close::Rollback,
            };
            let closing = (step, Permission::Destructive);
            let _: Closed = reported(ctx.out(), step, close(changes, router, mode, closing).await)?;
            Ok(applied(false))
        },
    )
    .await?;
    ctx.out().emit(&document, &ctx.out().tr(outcome, &[]))
}

/// Runs a `backup` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: creating and deleting write local state.
pub(crate) async fn backup(ctx: &Ctx, command: BackupCommand) -> Outcome {
    let services = ctx.services().await?;
    let out = ctx.out();
    let router = ctx.router_id(&services)?;
    match command {
        BackupCommand::Create { reason } => backup_create(ctx, &services, &reason).await,
        BackupCommand::List => {
            drop(
                ctx.authorize_audited(&services, &[Permission::Read], &[&router])
                    .await?,
            );
            let backups = services.backups().list(&router)?;
            let rows = backups
                .iter()
                .map(|info| {
                    vec![
                        info.name.clone(),
                        info.reason.clone(),
                        info.created_at.to_string(),
                    ]
                })
                .collect::<Vec<_>>();
            let document = json!({ "backups": backups.iter().map(|info| json!({ "name": info.name, "reason": info.reason, "created_at": info.created_at })).collect::<Vec<_>>() });
            out.table(
                &document,
                &[
                    keys::CLI_COL_NAME,
                    keys::CLI_COL_REASON,
                    keys::CLI_COL_CREATED,
                ],
                &rows,
            )
        }
        BackupCommand::Get { name, output } => {
            backup_get(ctx, &services, (&name, output.as_deref())).await
        }
        BackupCommand::Diff { older, newer } => {
            drop(
                ctx.authorize_audited(&services, &[Permission::Read], &[&router])
                    .await?,
            );
            let before = Lines::read(services.backups().get(&router, &older)?.expose_secret())?;
            let after = Lines::read(services.backups().get(&router, &newer)?.expose_secret())?;
            let changes = between(before.digests(), after.digests()).ok_or_else(|| {
                Failure::message(Exit::Validation, keys::CLI_BACKUP_DIFF_TOO_LARGE, &[])
            })?;
            let removed = changes
                .removed()
                .iter()
                .map(|&index| before.shown(index))
                .collect::<Vec<_>>();
            let added = changes
                .added()
                .iter()
                .map(|&index| after.shown(index))
                .collect::<Vec<_>>();
            let human = removed
                .iter()
                .map(|line| format!("- {line}"))
                .chain(added.iter().map(|line| format!("+ {line}")))
                .collect::<Vec<_>>()
                .join("\n");
            out.emit(&json!({ "removed": removed, "added": added }), &human)
        }
        BackupCommand::Delete { name } => {
            drop(
                ctx.authorize_audited(&services, &[Permission::Destructive], &[&router])
                    .await?,
            );
            let confirmation = confirm(out, ctx.globals(), Risk::Destructive, &router, false);
            ctx.confirmed(&services, &router, confirmation).await?;
            services.backups().delete(&router, &name)?;
            ctx.audit(
                &services,
                "cli.backup_delete",
                Some(&router),
                Value::Null,
                "success",
            )
            .await;
            out.emit(
                &json!({ "name": name, "deleted": true }),
                &out.tr(keys::CLI_DELETED, &[("name", &name)]),
            )
        }
    }
}

/// Backs up the router's startup configuration.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: writes the backup.
async fn backup_create(ctx: &Ctx, services: &Services, reason: &str) -> Outcome {
    let out = ctx.out();
    let router = ctx.router_id(services)?;
    let target = ctx.target(services, &[Permission::Write]).await?;
    let bytes = target
        .router()
        .client
        .download_config(ConfigKind::Startup)
        .await?;
    let text = str::from_utf8(bytes.expose_secret())
        .map_err(|_error| Failure::message(Exit::Router, keys::CLI_STARTUP_CONFIG_NOT_UTF8, &[]))?;
    let info = services
        .backups()
        .create(&router, reason, &SecretString::from(text.to_owned()))?;
    ctx.audit(
        services,
        "cli.backup_create",
        Some(&router),
        Value::Null,
        "success",
    )
    .await;
    out.emit(
        &json!({ "name": info.name, "created_at": info.created_at }),
        &info.name,
    )
}

/// Prints a backup redacted, or writes it in full to `output`.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: writes the output file.
async fn backup_get(
    ctx: &Ctx,
    services: &Services,
    (name, output): (&str, Option<&Path>),
) -> Outcome {
    let out = ctx.out();
    let router = ctx.router_id(services)?;
    let Some(path) = output else {
        drop(
            ctx.authorize_audited(services, &[Permission::Read], &[&router])
                .await?,
        );
        let text = services.backups().get(&router, name)?;
        let copy = redacted_copy(text.expose_secret())?;
        return out.emit(
            &json!({ "name": name, "redacted": true, "text": copy }),
            &copy,
        );
    };
    let reveal = [Permission::Read, Permission::RevealSecrets];
    drop(ctx.authorize_audited(services, &reveal, &[&router]).await?);
    let text = services.backups().get(&router, name)?;
    files::write_private(path, text.expose_secret().as_bytes(), true)?;
    ctx.audit(
        services,
        "cli.backup_get",
        Some(&router),
        json!({ "variant": "full" }),
        "success",
    )
    .await;
    out.emit(
        &json!({ "name": name, "written": path }),
        &out.tr(
            keys::CLI_CONFIG_WRITTEN,
            &[("path", &path.display().to_string())],
        ),
    )
}

/// Localized yes or no.
fn yes_no(out: super::output::Out, value: bool) -> String {
    out.tr(if value { keys::CLI_YES } else { keys::CLI_NO }, &[])
}
