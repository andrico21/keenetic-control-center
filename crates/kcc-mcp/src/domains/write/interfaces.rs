//! `kcc_interfaces_write` and `kcc_wan_write`.

use kcc_domain::{
    ChangeOp, DomainError, RouterCtx,
    interfaces::{self, SecurityLevel},
    wan::{self, StaticAddress},
};
use kcc_rci::ObjectName;
use schemars::JsonSchema;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::Value;

use super::common::{
    Opened, applied, apply_cli, begin, check_op, ipv4, needed, object, open, secret, text,
};
use crate::{
    KccMcp, McpFailure,
    domains::table::Area,
    support::{errors::map_domain, route::parse},
};

/// Interface write operations.
pub(super) const INTERFACE_OPS: &[&str] = &["up", "down", "description", "security_level"];

/// WAN write operations.
pub(super) const WAN_OPS: &[&str] = &[
    "create",
    "delete",
    "address_static",
    "address_dhcp",
    "identity",
    "password",
    "connect_via",
    "priority",
    "mtu",
    "default_route",
];

/// An interface security zone.
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum Level {
    /// Untrusted zone.
    Public,
    /// Trusted zone.
    Private,
    /// Isolated zone.
    Protected,
}

/// Arguments of `kcc_interfaces_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct InterfaceInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Confirms a change to the interface carrying the management connection.
    #[serde(default)]
    confirm: bool,
    /// Interface name.
    name: String,
    /// New description for `description`.
    #[serde(default)]
    description: Option<String>,
    /// Zone for `security_level`.
    #[serde(default)]
    level: Option<Level>,
}

/// Arguments of `kcc_wan_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct WanInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Confirms a change to the management connection.
    #[serde(default)]
    confirm: bool,
    /// Connection interface name.
    name: String,
    /// Identity, IPv4 address, or upstream interface name.
    #[serde(default)]
    value: Option<String>,
    /// IPv4 mask for `address_static`.
    #[serde(default)]
    mask: Option<String>,
    /// Priority or MTU.
    #[serde(default)]
    number: Option<i64>,
    /// Enables `default_route`.
    #[serde(default)]
    enabled: Option<bool>,
    /// PPP password for `password`; never returned or logged.
    #[serde(default)]
    #[schemars(with = "Option<String>")]
    secret: Option<SecretString>,
}

/// Runs one interface write through the guarded interface executor.
pub(super) async fn interfaces(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: InterfaceInput = parse(arguments)?;
    check_op(INTERFACE_OPS, &input.op)?;
    let opened = open(
        server,
        Area::Interfaces,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let (_identity, _router, ctx) = &opened;
    let name = object(Some(&input.name))?;
    let operation = match input.op.as_str() {
        "up" => interfaces::plan_up(ctx, &name),
        "down" => {
            let verdict = interfaces::detect_management(ctx, &name)
                .await
                .map_err(map_domain)?;
            interfaces::plan_down(ctx, &name, verdict)
        }
        "description" => {
            interfaces::plan_description(ctx, &name, text(input.description.as_deref())?)
        }
        _ => {
            let verdict = interfaces::detect_management(ctx, &name)
                .await
                .map_err(map_domain)?;
            let level = match needed(input.level)? {
                Level::Public => SecurityLevel::Public,
                Level::Private => SecurityLevel::Private,
                Level::Protected => SecurityLevel::Protected,
            };
            interfaces::plan_security_level(ctx, &name, level, verdict)
        }
    }
    .map_err(map_domain)?;
    let mut changes = begin(server, &opened).await?;
    let result = interfaces::apply(&mut changes, ctx, &name, operation, input.confirm)
        .await
        .map_err(|error| {
            if error.is_confirmation_required() {
                McpFailure::ConfirmRequired
            } else {
                tracing::warn!(error = ?error, "MCP interface change failed");
                McpFailure::Conflict
            }
        })?;
    Ok(applied(result.unsaved))
}

/// Plans one WAN change.
async fn plan_wan(
    ctx: &RouterCtx,
    name: &ObjectName,
    input: WanInput,
) -> Result<Result<ChangeOp, DomainError>, McpFailure> {
    Ok(match input.op.as_str() {
        "create" => wan::plan_create(ctx, name),
        "delete" => wan::plan_delete(ctx, name),
        "address_static" => {
            let address =
                StaticAddress::new(ipv4(input.value.as_deref())?, ipv4(input.mask.as_deref())?);
            let verdict = interfaces::detect_management(ctx, name)
                .await
                .map_err(map_domain)?;
            wan::plan_static_address(ctx, name, address, verdict)
        }
        "address_dhcp" => {
            let verdict = interfaces::detect_management(ctx, name)
                .await
                .map_err(map_domain)?;
            wan::plan_dhcp(ctx, name, verdict)
        }
        "identity" => wan::plan_identity(ctx, name, text(input.value.as_deref())?),
        "password" => wan::plan_password(ctx, name, secret(input.secret)?),
        "connect_via" => wan::plan_connect_via(ctx, name, &object(input.value.as_deref())?),
        "priority" => wan::plan_priority(ctx, name, needed(input.number)?),
        "mtu" => wan::plan_mtu(ctx, name, needed(input.number)?),
        _ => wan::plan_default_route(ctx, name, needed(input.enabled)?),
    })
}

/// Runs one WAN write.
pub(super) async fn wan(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: WanInput = parse(arguments)?;
    check_op(WAN_OPS, &input.op)?;
    let opened: Opened = open(
        server,
        Area::Wan,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let name = object(Some(&input.name))?;
    let confirm = input.confirm;
    let planned = plan_wan(&opened.2, &name, input).await?;
    apply_cli(
        server,
        &opened,
        (planned, confirm, |operation: &ChangeOp| {
            wan::change_request(&name, operation)
        }),
    )
    .await
}
