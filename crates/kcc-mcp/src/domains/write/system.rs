//! `kcc_system_write`.

use kcc_domain::{
    ChangeOp, DomainError, RouterCtx,
    system::{self, FactoryResetError},
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use super::common::{applied, apply, apply_registered, check_op, needed, open, text};
use crate::{
    KccMcp, McpFailure,
    domains::table::Area,
    support::{
        errors::{map_domain, map_workflow},
        route::parse,
    },
};

/// System write operations.
pub(super) const OPS: &[&str] = &[
    "hostname",
    "domainname",
    "description",
    "timezone",
    "ntp_server",
    "ntp_master",
    "ntp_sync_period",
    "reboot",
    "factory_reset",
];

/// Arguments of `kcc_system_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Confirms a management or destructive operation.
    #[serde(default)]
    confirm: bool,
    /// New value: hostname, domain, description, timezone locality, or NTP server.
    #[serde(default)]
    value: Option<String>,
    /// Enables `ntp_master`.
    #[serde(default)]
    enabled: Option<bool>,
    /// NTP sync period in seconds.
    #[serde(default)]
    seconds: Option<u32>,
    /// The router profile id typed again to confirm `factory_reset`.
    #[serde(default)]
    confirm_name: Option<String>,
}

/// Plans a non-terminal system change.
fn plan(ctx: &RouterCtx, input: &Input) -> Result<Result<ChangeOp, DomainError>, McpFailure> {
    let value = || text(input.value.as_deref());
    Ok(match input.op.as_str() {
        "hostname" => system::plan_hostname(ctx, value()?),
        "domainname" => system::plan_domainname(ctx, value()?),
        "description" => system::plan_description(ctx, value()?),
        "timezone" => system::plan_timezone(ctx, value()?),
        "ntp_server" => system::plan_ntp_server(ctx, value()?),
        "ntp_master" => system::plan_ntp_master(ctx, needed(input.enabled)?),
        _ => system::plan_ntp_sync_period(ctx, needed(input.seconds)?),
    })
}

/// Runs one system write.
// NOT cancel-safe: transmitted work may precede verification or recovery cleanup.
pub(super) async fn write(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: Input = parse(arguments)?;
    check_op(OPS, &input.op)?;
    let opened = open(
        server,
        Area::System,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let (_identity, router, ctx) = &opened;
    match input.op.as_str() {
        "reboot" => {
            drop(
                apply_registered(
                    server,
                    &opened,
                    (Area::System, &input.op, input.confirm, async |changes| {
                        system::reboot(changes, ctx).await.map_err(map_workflow)
                    }),
                )
                .await?,
            );
            Ok(json!({ "applied": true, "rebooting": true }))
        }
        "factory_reset" => {
            let typed = text(input.confirm_name.as_deref())?;
            system::confirm_factory_reset(router.as_str(), typed)
                .map_err(|_error| McpFailure::InvalidArguments)?;
            drop(
                apply_registered(
                    server,
                    &opened,
                    (Area::System, &input.op, input.confirm, async |changes| {
                        system::factory_reset(changes, ctx, router.as_str(), typed)
                            .await
                            .map_err(|error| match error {
                                FactoryResetError::ConfirmationMismatch => {
                                    McpFailure::InvalidArguments
                                }
                                FactoryResetError::Domain(domain) => map_domain(domain),
                                FactoryResetError::Workflow(workflow) => map_workflow(workflow),
                                _ => McpFailure::Internal,
                            })
                    }),
                )
                .await?,
            );
            Ok(json!({ "applied": true, "factory_reset": true }))
        }
        _ => {
            let operation = plan(ctx, &input)?.map_err(map_domain)?;
            let request = system::change_request(&operation).map_err(map_domain)?;
            let result = apply(
                server,
                &opened,
                (&operation, input.confirm, async |changes| {
                    changes.apply(request).await.map_err(map_workflow)
                }),
            )
            .await?;
            Ok(applied(result.unsaved, &result.audit))
        }
    }
}
