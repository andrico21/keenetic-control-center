//! `kcc_logging_write`, `kcc_schedules_write`, and `kcc_storage_write`.

use kcc_domain::{
    ChangeOp, DomainError, RouterCtx, logging,
    schedules::{self, ActionTime, ScheduleAction},
    storage::{self, MaintenanceAction, MaintenanceRequest},
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use super::common::{Opened, apply_cli, check_op, needed, open, text};
use crate::{KccMcp, McpFailure, domains::table::Area, support::route::parse};

/// Logging write operations.
pub(super) const LOGGING_OPS: &[&str] = &["server", "reduction", "suppress", "clear"];

/// Schedule write operations.
pub(super) const SCHEDULE_OPS: &[&str] = &["create", "description", "action"];

/// Storage write operations.
pub(super) const STORAGE_OPS: &[&str] = &["eject", "partition_check", "partition_format"];

/// The area a housekeeping write belongs to.
#[derive(Clone, Copy, Debug)]
pub(super) enum Chore {
    /// Log configuration.
    Logging,
    /// Schedules.
    Schedules,
    /// Storage maintenance.
    Storage,
}

/// Arguments of the logging, schedule, and storage write tools.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct HousekeepingInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Confirms a destructive operation.
    #[serde(default)]
    confirm: bool,
    /// Log server address, suppressed ident, schedule name, media, or partition.
    #[serde(default)]
    name: Option<String>,
    /// Schedule description, schedule action (`start` or `stop`), or filesystem.
    #[serde(default)]
    value: Option<String>,
    /// Log server port.
    #[serde(default)]
    port: Option<u16>,
    /// Flag for enable operations.
    #[serde(default)]
    enabled: Option<bool>,
    /// Schedule action minute, hour, and day of week.
    #[serde(default)]
    at: Option<[u8; 3]>,
}

/// Plans one logging change.
fn plan_logging(
    opened: &Opened,
    input: &HousekeepingInput,
) -> Result<Result<ChangeOp, DomainError>, McpFailure> {
    let (identity, router, ctx) = opened;
    Ok(match input.op.as_str() {
        "server" => logging::plan_server(
            ctx,
            text(input.name.as_deref())?,
            input.port,
            needed(input.enabled)?,
        ),
        "reduction" => logging::plan_reduction(ctx, needed(input.enabled)?),
        "suppress" => {
            logging::plan_suppress(ctx, text(input.name.as_deref())?, needed(input.enabled)?)
        }
        _ => logging::plan_clear(ctx, router.as_str(), &identity.role, input.confirm),
    })
}

/// Plans one schedule change.
fn plan_schedule(
    ctx: &RouterCtx,
    input: &HousekeepingInput,
) -> Result<Result<ChangeOp, DomainError>, McpFailure> {
    let name = text(input.name.as_deref())?;
    Ok(match input.op.as_str() {
        "create" => schedules::plan_create(ctx, name),
        "description" => schedules::plan_description(ctx, name, text(input.value.as_deref())?),
        _ => {
            let action = match text(input.value.as_deref())? {
                "start" => ScheduleAction::Start,
                "stop" => ScheduleAction::Stop,
                _ => return Err(McpFailure::InvalidArguments),
            };
            let [minute, hour, day] = needed(input.at)?;
            schedules::plan_action(ctx, name, ActionTime::new(action, minute, hour, day))
        }
    })
}

/// Plans one storage operation; every one is destructive and needs confirmation.
fn plan_storage(
    opened: &Opened,
    input: &HousekeepingInput,
) -> Result<Result<ChangeOp, DomainError>, McpFailure> {
    let (identity, router, ctx) = opened;
    let name = text(input.name.as_deref())?;
    Ok(match input.op.as_str() {
        "eject" => storage::plan_eject(ctx, router.as_str(), &identity.role, name, input.confirm),
        operation => {
            let action = if operation == "partition_check" {
                MaintenanceAction::Check
            } else {
                MaintenanceAction::Format
            };
            let filesystem = input
                .value
                .as_deref()
                .map(|value| text(Some(value)))
                .transpose()?;
            let request = MaintenanceRequest::new(
                router.as_str(),
                &identity.role,
                name,
                filesystem,
                input.confirm,
            );
            storage::plan_maintenance(ctx, action, request)
        }
    })
}

/// Runs one logging, schedule, or storage write.
pub(super) async fn housekeeping(
    server: &KccMcp,
    chore: Chore,
    arguments: Value,
) -> Result<Value, McpFailure> {
    let input: HousekeepingInput = parse(arguments)?;
    let (ops, area) = match chore {
        Chore::Logging => (LOGGING_OPS, Area::Logging),
        Chore::Schedules => (SCHEDULE_OPS, Area::Schedules),
        Chore::Storage => (STORAGE_OPS, Area::Storage),
    };
    check_op(ops, &input.op)?;
    let opened = open(server, area, (input.host.clone(), &input.op, input.confirm)).await?;
    match chore {
        Chore::Logging => {
            let planned = plan_logging(&opened, &input)?;
            apply_cli(
                server,
                &opened,
                (planned, input.confirm, logging::change_request),
            )
            .await
        }
        Chore::Schedules => {
            let planned = plan_schedule(&opened.2, &input)?;
            apply_cli(
                server,
                &opened,
                (planned, input.confirm, schedules::change_request),
            )
            .await
        }
        Chore::Storage => {
            let planned = plan_storage(&opened, &input)?;
            apply_cli(
                server,
                &opened,
                (planned, input.confirm, storage::change_request),
            )
            .await
        }
    }
}
