//! `kcc_wifi_write` and `kcc_mesh_write`.

use kcc_domain::{
    ChangeOp, DomainError, RouterCtx,
    mesh::{self, RebootError},
    wifi::{self, Encryption},
};
use kcc_rci::ObjectName;
use schemars::JsonSchema;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Value, json};

use super::common::{apply_cli, begin, check_op, needed, object, open, secret, text};
use crate::{
    KccMcp, McpFailure,
    domains::table::Area,
    support::{
        errors::{map_domain, map_workflow},
        route::parse,
    },
};

/// Wi-Fi write operations.
pub(super) const WIFI_OPS: &[&str] = &[
    "ssid",
    "wpa_psk",
    "encryption_enable",
    "encryption_wpa2",
    "encryption_wpa3",
    "hide_ssid",
    "up",
    "schedule",
    "channel",
    "channel_width",
    "power",
    "country_code",
    "band_steering",
];

/// Mesh write operations.
pub(super) const MESH_OPS: &[&str] = &["acquire", "member_reboot", "update_check", "update_start"];

/// Arguments of `kcc_wifi_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct WifiInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Confirms a management change.
    #[serde(default)]
    confirm: bool,
    /// Access point or radio interface name.
    name: String,
    /// SSID, schedule name, channel, channel width, or country code.
    #[serde(default)]
    value: Option<String>,
    /// Transmit power.
    #[serde(default)]
    number: Option<i64>,
    /// Flag for `hide_ssid`, `up`, and `band_steering`.
    #[serde(default)]
    enabled: Option<bool>,
    /// WPA pre-shared key for `wpa_psk`; never returned or logged.
    #[serde(default)]
    #[schemars(with = "Option<String>")]
    secret: Option<SecretString>,
}

/// Arguments of `kcc_mesh_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct MeshInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Confirms `member_reboot`.
    #[serde(default)]
    confirm: bool,
    /// Candidate or member id.
    member: String,
    /// The member id typed again to confirm `member_reboot`.
    #[serde(default)]
    confirm_name: Option<String>,
}

/// Plans one Wi-Fi change.
fn plan_wifi(
    ctx: &RouterCtx,
    name: &ObjectName,
    input: WifiInput,
) -> Result<Result<ChangeOp, DomainError>, McpFailure> {
    let value = input.value.as_deref();
    Ok(match input.op.as_str() {
        "ssid" => wifi::plan_ssid(ctx, name, text(value)?),
        "wpa_psk" => wifi::plan_wpa_psk(ctx, name, secret(input.secret)?),
        "encryption_enable" => wifi::plan_encryption(ctx, name, Encryption::Enable),
        "encryption_wpa2" => wifi::plan_encryption(ctx, name, Encryption::Wpa2),
        "encryption_wpa3" => wifi::plan_encryption(ctx, name, Encryption::Wpa3),
        "hide_ssid" => wifi::plan_hide_ssid(ctx, name, needed(input.enabled)?),
        "up" => wifi::plan_up(ctx, name, needed(input.enabled)?),
        "schedule" => wifi::plan_schedule(ctx, name, text(value)?),
        "channel" => wifi::plan_channel(ctx, name, text(value)?),
        "channel_width" => wifi::plan_channel_width(ctx, name, text(value)?),
        "power" => wifi::plan_power(ctx, name, needed(input.number)?),
        "country_code" => wifi::plan_country_code(ctx, name, text(value)?),
        _ => wifi::plan_band_steering(ctx, name, needed(input.enabled)?),
    })
}

/// Runs one Wi-Fi write.
pub(super) async fn wifi(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: WifiInput = parse(arguments)?;
    check_op(WIFI_OPS, &input.op)?;
    let opened = open(
        server,
        Area::Wifi,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let name = object(Some(&input.name))?;
    let confirm = input.confirm;
    let planned = plan_wifi(&opened.2, &name, input)?;
    apply_cli(
        server,
        &opened,
        (planned, confirm, |operation: &ChangeOp| {
            wifi::change_request(&name, operation)
        }),
    )
    .await
}

/// Runs one mesh write.
pub(super) async fn mesh(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: MeshInput = parse(arguments)?;
    check_op(MESH_OPS, &input.op)?;
    let opened = open(
        server,
        Area::Mesh,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let ctx = &opened.2;
    let member = text(Some(&input.member))?;
    let planned = match input.op.as_str() {
        "acquire" => mesh::plan_acquire(ctx, member),
        "update_check" => mesh::plan_update_check(ctx, member),
        "update_start" => mesh::plan_update_start(ctx, member),
        _ => {
            let typed = text(input.confirm_name.as_deref())?;
            let mut changes = begin(server, &opened).await?;
            drop(
                mesh::reboot_member(&mut changes, ctx, member, typed)
                    .await
                    .map_err(|error| match error {
                        RebootError::ConfirmationMismatch => McpFailure::InvalidArguments,
                        RebootError::Domain(domain) => map_domain(domain),
                        RebootError::Workflow(workflow) => map_workflow(workflow),
                        _ => McpFailure::Internal,
                    })?,
            );
            return Ok(json!({ "applied": true, "rebooting": member }));
        }
    };
    apply_cli(
        server,
        &opened,
        (planned, input.confirm, mesh::change_request),
    )
    .await
}
