//! `kcc_system_write`.

use kcc_domain::system;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use super::common::{applied, apply, apply_registered, needed, open, text};
use crate::{
    KccMcp, McpFailure,
    domains::table::Area,
    support::{
        errors::{map_domain, map_workflow},
        route::parse,
        shape::noting,
    },
};

/// A system write operation.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Op {
    /// Sets the hostname.
    Hostname,
    /// Sets the domain name.
    Domainname,
    /// Sets the description.
    Description,
    /// Sets the timezone.
    Timezone,
    /// Sets the NTP server.
    NtpServer,
    /// Turns the NTP server role on or off.
    NtpMaster,
    /// Sets the NTP sync period.
    NtpSyncPeriod,
    /// Reboots the router.
    Reboot,
    /// Resets the router to factory defaults.
    FactoryReset,
}

impl Op {
    /// The operation's wire name.
    const fn name(self) -> &'static str {
        match self {
            Self::Hostname => "hostname",
            Self::Domainname => "domainname",
            Self::Description => "description",
            Self::Timezone => "timezone",
            Self::NtpServer => "ntp_server",
            Self::NtpMaster => "ntp_master",
            Self::NtpSyncPeriod => "ntp_sync_period",
            Self::Reboot => "reboot",
            Self::FactoryReset => "factory_reset",
        }
    }
}

/// System write operations.
pub(super) const OPS: &[&str] = &[
    Op::Hostname.name(),
    Op::Domainname.name(),
    Op::Description.name(),
    Op::Timezone.name(),
    Op::NtpServer.name(),
    Op::NtpMaster.name(),
    Op::NtpSyncPeriod.name(),
    Op::Reboot.name(),
    Op::FactoryReset.name(),
];

/// Arguments of `kcc_system_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    /// Router profile id.
    host: String,
    /// Write operation.
    #[schemars(with = "String")]
    op: Op,
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

/// Runs one system write.
// NOT cancel-safe: transmitted work may precede verification or recovery cleanup.
pub(super) async fn write(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: Input = parse(arguments)?;
    let op = input.op.name();
    let opened = open(
        server,
        Area::System,
        (input.host.clone(), op, input.confirm),
    )
    .await?;
    let (_identity, router, ctx) = &opened;
    let value = || text(input.value.as_deref());
    let planned = match input.op {
        Op::Reboot => {
            let result = apply_registered(
                server,
                &opened,
                (Area::System, op, input.confirm, async |changes| {
                    system::reboot(changes, ctx).await.map_err(map_workflow)
                }),
            )
            .await?;
            let reply = json!({ "applied": true, "rebooting": true });
            return Ok(noting(reply, &result.audit));
        }
        Op::FactoryReset => {
            let typed = text(input.confirm_name.as_deref())?;
            system::confirm_factory_reset(router.as_str(), typed)
                .map_err(|_error| McpFailure::InvalidArguments)?;
            let result = apply_registered(
                server,
                &opened,
                (Area::System, op, input.confirm, async |changes| {
                    system::factory_reset(changes, ctx, router.as_str(), typed)
                        .await
                        .map_err(|error| map_workflow(error.into()))
                }),
            )
            .await?;
            let reply = json!({ "applied": true, "factory_reset": true });
            return Ok(noting(reply, &result.audit));
        }
        Op::Hostname => system::plan_hostname(ctx, value()?),
        Op::Domainname => system::plan_domainname(ctx, value()?),
        Op::Description => system::plan_description(ctx, value()?),
        Op::Timezone => system::plan_timezone(ctx, value()?),
        Op::NtpServer => system::plan_ntp_server(ctx, value()?),
        Op::NtpMaster => system::plan_ntp_master(ctx, needed(input.enabled)?),
        Op::NtpSyncPeriod => system::plan_ntp_sync_period(ctx, needed(input.seconds)?),
    };
    let operation = planned.map_err(map_domain)?;
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
