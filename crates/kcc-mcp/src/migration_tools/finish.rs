//! `kcc_migration_finish` and `kcc_migration_report`.

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use kcc_migrate::apply::ApplyError;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use super::apply::map_apply;
use crate::{
    KccMcp, McpFailure, authorize_routers,
    support::{
        route::parse,
        validate::{parse_cursor, valid_job_id},
    },
};

/// How an applied migration ends.
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FinishAction {
    /// Save the verified changes.
    Commit,
    /// Restore the target's pre-apply startup configuration (destructive).
    Rollback,
}

/// Arguments of `kcc_migration_finish`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinishInput {
    /// Target router profile id.
    host: String,
    /// Plan id.
    plan_id: String,
    /// Commit or rollback.
    action: FinishAction,
    /// Required: confirms the action.
    #[serde(default)]
    confirm: bool,
}

/// Arguments of `kcc_migration_report`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReportInput {
    /// Target router profile id.
    host: String,
    /// Plan id.
    plan_id: String,
    /// Decimal offset into the plan items.
    #[serde(default)]
    cursor: Option<String>,
    /// Items page size, at most 100 (default 50).
    #[serde(default)]
    limit: Option<u16>,
}

/// Commits or rolls back an applied migration.
pub(crate) async fn finish(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: FinishInput = parse(arguments)?;
    valid_job_id(&input.plan_id)?;
    let (identity, _host) = server.authorize_host(Permission::Migrate, input.host.clone())?;
    let mut entries = server.migrations.lock().await;
    let migration = entries
        .get_mut(&input.plan_id)
        .ok_or(McpFailure::InvalidArguments)?;
    let routers = migration.routers_for(&identity)?;
    let [_source, target] = &routers;
    if target.as_str() != input.host {
        return Err(McpFailure::InvalidArguments);
    }
    authorize_routers(&identity, Permission::Migrate, &routers)?;
    if !input.confirm {
        return Err(McpFailure::ConfirmRequired);
    }
    let applier = migration.applier_mut().ok_or(McpFailure::Conflict)?;
    let result = match input.action {
        FinishAction::Commit => {
            authorize_routers(&identity, Permission::Save, core::slice::from_ref(target))
                .map_err(|_forbidden| McpFailure::ManagementNotCommittedFailSafeArmed)?;
            applier.commit().await
        }
        FinishAction::Rollback => {
            server.require_destructive(Risk::Destructive, input.confirm)?;
            applier.rollback().await
        }
    };
    if let Err(error) = result {
        if error == ApplyError::RollbackRestarting {
            migration.close();
        }
        return Err(map_apply(error));
    }
    migration.close();
    let value = migration.summary();
    drop(entries);
    Ok(value)
}

/// Reads the plan counts, one page of redacted items, and the apply outcome.
pub(crate) async fn report(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: ReportInput = parse(arguments)?;
    valid_job_id(&input.plan_id)?;
    let offset = parse_cursor(input.cursor.as_deref())?;
    let limit = usize::from(input.limit.unwrap_or(50).clamp(1, 100));
    let identity = server.identity()?;
    let entries = server.migrations.lock().await;
    let migration = entries
        .get(&input.plan_id)
        .ok_or(McpFailure::InvalidArguments)?;
    let (routers, mut value, page) = (
        migration.routers_for(&identity)?,
        migration.summary(),
        migration.items(offset, limit),
    );
    drop(entries);
    let [_source, target] = &routers;
    if target.as_str() != input.host {
        return Err(McpFailure::InvalidArguments);
    }
    authorize_routers(&identity, Permission::Migrate, &routers)?;
    if let (Value::Object(summary), Value::Object(items)) = (&mut value, page) {
        summary.extend(items);
    }
    Ok(value)
}
