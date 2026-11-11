//! `kcc_preset_apply`: a dry-run plan, or the protected apply under the router safety timer.

use alloc::sync::Arc;

use kcc_app::{
    audit::{Actor, ActorKind},
    permissions::Permission,
};
use kcc_domain::configuration::SafetyNet;
use kcc_i18n::locale::Locale;
use kcc_migrate::{
    apply::Applier,
    presets::apply::{PresetApplyError, PresetApplyRequest, request},
    report::MigrationReport,
};
use serde_json::{Value, json};

use super::plan::ApplyInput;
use crate::{
    KccMcp, McpFailure, authorize_routers,
    migration_tools::{
        apply::{follow, map_apply},
        state::Migration,
    },
    support::route::{Progress, parse},
};

/// Maps a preset apply refusal.
const fn map_request(error: PresetApplyError) -> McpFailure {
    match error {
        PresetApplyError::Forbidden => McpFailure::Forbidden,
        PresetApplyError::PlanNotReady => McpFailure::Conflict,
        PresetApplyError::InvalidPlan | _ => McpFailure::ValidationFailed,
    }
}

/// Plans (`dry_run`) or applies a preset; an apply returns once its apply phase ends and
/// is finished with `kcc_migration_finish` under the returned `plan_id`.
pub(crate) async fn apply(
    server: &KccMcp,
    arguments: Value,
    progress: Option<Progress>,
) -> Result<Value, McpFailure> {
    let input: ApplyInput = parse(arguments)?;
    let (identity, host) = server.authorize_host(Permission::Migrate, input.host().to_owned())?;
    if !input.dry_run() {
        authorize_routers(
            &identity,
            SafetyNet::CONTROL_PERMISSION,
            core::slice::from_ref(&host),
        )?;
    }
    let planned = input.planned(server, &identity).await?;
    if input.dry_run() || !planned.is_ready() {
        return planned.view(input.dry_run());
    }
    let audit = server.audit.clone().ok_or(McpFailure::Internal)?;
    let (source, target, preset, plan, inventory) = planned.into_parts();
    let preset_id = preset.id.clone();
    let mut reviewed = PresetApplyRequest::new(
        Arc::clone(&server.workflow),
        audit,
        Actor::new(ActorKind::Mcp, identity.name.clone()),
        identity.role.clone(),
        target.as_str().to_owned(),
        preset,
        plan,
        inventory,
    );
    reviewed.options = input.options();
    let protected = request(reviewed).map_err(map_request)?;
    let migration_plan = protected.plan.clone();
    let report = MigrationReport::from_plan(&migration_plan, Locale::En);
    let plan_id = migration_plan.plan_id.clone();
    let mut events = server.jobs.subscribe();
    let (job, done) = Applier::start(&server.jobs, protected)
        .await
        .map_err(map_apply)?;
    let applier = follow(&job, &mut events, done, progress.as_ref())
        .await
        .map_err(map_apply)?;
    let mut migration = Migration::new(
        identity.name,
        (source.unwrap_or_else(|| target.clone()), target),
        (migration_plan, report, Vec::new()),
    );
    migration.record_apply(job.clone(), applier);
    let mut value = migration.summary();
    drop(server.migrations.lock().await.insert(plan_id, migration));
    if let Value::Object(summary) = &mut value {
        drop(summary.insert("job_id".to_owned(), json!(job)));
        drop(summary.insert("preset_id".to_owned(), json!(preset_id)));
        drop(summary.insert("status".to_owned(), json!("applied")));
    }
    Ok(value)
}
