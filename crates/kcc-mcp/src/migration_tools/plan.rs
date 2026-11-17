//! `kcc_migration_inventory` and `kcc_migration_plan`.

use alloc::collections::BTreeSet;

use kcc_app::permissions::Permission;
use kcc_i18n::locale::Locale;
use kcc_migrate::{
    inventory::{InventoryClient, InventoryError, TargetInventory},
    planner::{Choices, MigrationMaps, PlanError, Planner},
    report::MigrationReport,
    source::SourceConfig,
};
use kcc_rci::{ConfigKind, capabilities::SupportTier, version::FirmwareVersion};
use schemars::JsonSchema;
use secrecy::ExposeSecret as _;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    select::{MAX_CHOICES, overwrite_keys, without},
    state::Migration,
};
use crate::{
    KccMcp, McpFailure, McpIdentity, RouterId, authorize_routers,
    support::{
        errors::map_rci,
        names,
        route::parse,
        validate::{parse_cursor, valid_job_id},
    },
};

/// Arguments of `kcc_migration_inventory`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct InventoryInput {
    /// Target router profile id.
    host: String,
}

/// Arguments of `kcc_migration_plan`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlanInput {
    /// Target router profile id.
    host: String,
    /// Source router profile id; its startup configuration is migrated.
    source: String,
    /// Acknowledges a target whose firmware support is documentation-based.
    #[serde(default)]
    ack_documentation_tier: bool,
    /// Source setting indices whose conflicting value overwrites the target's.
    #[serde(default)]
    overwrite: Vec<usize>,
    /// Source setting indices left out of the migration.
    #[serde(default)]
    exclude: Vec<usize>,
    /// Decimal offset into the plan items.
    #[serde(default)]
    cursor: Option<String>,
    /// Items page size, at most 100 (default 50).
    #[serde(default)]
    limit: Option<u16>,
}

/// Maps a target inventory failure.
fn map_inventory(error: InventoryError) -> McpFailure {
    match error {
        InventoryError::Rci(rci) => map_rci(&rci),
        InventoryError::SourceVersionRequired
        | InventoryError::UnsupportedFirmware
        | InventoryError::TargetFirmwareOlder {
            source_version: _,
            target_version: _,
        } => McpFailure::ValidationFailed,
        InventoryError::ConfigEncoding | InventoryError::Parse(_) | InventoryError::Catalog | _ => {
            McpFailure::Internal
        }
    }
}

/// Collects the read-only inventory of `target` for `source_firmware`.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(crate) async fn collect(
    server: &KccMcp,
    identity: &McpIdentity,
    target: &RouterId,
    source_firmware: Option<FirmwareVersion>,
) -> Result<TargetInventory, McpFailure> {
    let client = server
        .registry
        .bootstrap_client(&identity.role, target.as_str())
        .await
        .map_err(|error| {
            tracing::warn!(target = target.as_str(), error = ?error, "MCP migration target unavailable");
            McpFailure::RouterUnreachable
        })?;
    TargetInventory::collect(&InventoryClient::from_client(&client), source_firmware)
        .await
        .map_err(map_inventory)
}

/// Reads the target's migration inventory.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(crate) async fn inventory(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: InventoryInput = parse(arguments)?;
    let (identity, target) = server.authorize_host(Permission::Migrate, input.host)?;
    let firmware = server
        .registry
        .poll_info(target.as_str())
        .await
        .map_err(|_error| McpFailure::RouterUnreachable)?
        .firmware;
    let found = collect(server, &identity, &target, firmware).await?;
    Ok(json!({
        "host": target.as_str(),
        "model": found.info.version.model,
        "firmware": found.info.firmware.map(|version| version.to_string()),
        "support_tier": tier_name(found.info.support_tier()),
        "system_mode": found.system_mode.as_ref().map(names::system_mode),
        "fail_safe_available": found.fail_safe_available,
        "ports": found.ports.iter().map(|port| json!({"id": port.id, "label": port.label})).collect::<Vec<_>>(),
        "radios": found.radios.iter().map(|radio| radio.id.clone()).collect::<Vec<_>>(),
        "interfaces": found.interfaces.iter().map(|interface| json!({"name": interface.name, "kind": interface.kind})).collect::<Vec<_>>(),
        "installed_components": found.installed_components,
        "available_components": found.available_components
    }))
}

/// Stable support tier name.
const fn tier_name(tier: SupportTier) -> &'static str {
    match tier {
        SupportTier::HardwareVerified => "hardware_verified",
        SupportTier::DocumentationBased => "documentation_based",
        SupportTier::Unsupported | _ => "unsupported",
    }
}

/// Reads and parses the source router's startup configuration.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
async fn source_config(server: &KccMcp, source: &RouterId) -> Result<SourceConfig, McpFailure> {
    let client = server
        .registry
        .client(source.as_str())
        .await
        .map_err(|_error| McpFailure::RouterUnreachable)?;
    let bytes = client
        .download_config(ConfigKind::Startup)
        .await
        .map_err(|error| map_rci(&error))?;
    SourceConfig::from_bytes(bytes.expose_secret()).map_err(|_error| McpFailure::ValidationFailed)
}

/// Plans a migration from `source` onto `host`, or lists the items that block it.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(crate) async fn plan(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: PlanInput = parse(arguments)?;
    if input.overwrite.len() > MAX_CHOICES || input.exclude.len() > MAX_CHOICES {
        return Err(McpFailure::InvalidArguments);
    }
    let source = RouterId::new(input.source)?;
    let target = RouterId::new(input.host)?;
    if source == target {
        return Err(McpFailure::InvalidArguments);
    }
    let identity = server.identity()?;
    authorize_routers(
        &identity,
        Permission::Migrate,
        &[source.clone(), target.clone()],
    )?;
    let offset = parse_cursor(input.cursor.as_deref())?;
    let limit = usize::from(input.limit.unwrap_or(50).clamp(1, 100));
    let whole = source_config(server, &source).await?;
    let found = collect(server, &identity, &target, whole.firmware).await?;
    match found.info.support_tier() {
        SupportTier::HardwareVerified => {}
        SupportTier::DocumentationBased if input.ack_documentation_tier => {}
        SupportTier::DocumentationBased => return Err(McpFailure::UnverifiedFirmwareTier),
        SupportTier::Unsupported | _ => return Err(McpFailure::ValidationFailed),
    }
    let (trimmed, kept) = without(
        &whole,
        &input.exclude.iter().copied().collect::<BTreeSet<_>>(),
    );
    let mut choices = Choices::default();
    choices.overwrite_scalars = overwrite_keys(
        &whole,
        &input.overwrite.iter().copied().collect::<BTreeSet<_>>(),
    );
    let planned = match Planner::plan(&trimmed, &found, &MigrationMaps::default(), &choices) {
        Ok(planned) => planned,
        Err(PlanError::PlanBlocked { items }) => {
            let blocked = items
                .iter()
                .map(|item| {
                    json!({
                        "source_index": kept.get(item.source_index).copied(),
                        "disposition": item.disposition,
                        "reason": item.reason_key,
                        "needed_input": item.needed_input
                    })
                })
                .collect::<Vec<_>>();
            return Ok(json!({ "status": "blocked", "blocked": blocked }));
        }
        Err(error) => {
            tracing::error!(error = ?error, "MCP migration planning failed");
            return Err(McpFailure::Internal);
        }
    };
    let report = MigrationReport::from_plan(&planned, Locale::En);
    let id = planned.plan_id.clone();
    valid_job_id(&id).map_err(|_error| McpFailure::Internal)?;
    let migration = Migration::new(identity.name, (source, target), (planned, report, kept));
    let mut value = migration.summary();
    let page = migration.items(offset, limit);
    if let (Value::Object(summary), Value::Object(items)) = (&mut value, page) {
        summary.extend(items);
        drop(summary.insert("status".to_owned(), json!("planned")));
    }
    drop(server.migrations.record(migration)?);
    Ok(value)
}
