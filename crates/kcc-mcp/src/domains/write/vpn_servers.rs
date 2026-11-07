//! `kcc_vpn_servers_write`.

use kcc_domain::vpn_servers::{self, VpnServerChange, VpnServerService, secrets as server_secrets};
use schemars::JsonSchema;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Value, json};

use super::common::{apply_cli, begin, check_op, needed, object, open, secret, text};
use crate::{
    KccMcp, McpFailure,
    domains::table::Area,
    support::{errors::map_workflow, route::parse},
};

/// VPN server operations.
pub(super) const OPS: &[&str] = &[
    "vpn_service",
    "sstp_service",
    "ipsec_service",
    "openconnect_service",
    "vpn_interface",
    "vpn_pool",
    "sstp_interface",
    "sstp_pool",
    "wireguard_interface",
    "openconnect_interface",
    "openconnect_pool",
    "ipsec_virtual_ip",
    "ike_psk",
    "password",
];

/// Arguments of `kcc_vpn_servers_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct VpnServerInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Confirms a management operation.
    #[serde(default)]
    confirm: bool,
    /// Server interface, crypto map, IKE key, or user name.
    #[serde(default)]
    name: Option<String>,
    /// Flag for service and enable operations.
    #[serde(default)]
    enabled: Option<bool>,
    /// Pool size.
    #[serde(default)]
    number: Option<u16>,
    /// First pool address.
    #[serde(default)]
    value: Option<String>,
    /// IKE pre-shared key or user password; never returned or logged.
    #[serde(default)]
    #[schemars(with = "Option<String>")]
    secret: Option<SecretString>,
}

/// Builds the curated VPN server change of `input`.
fn server_change(input: &VpnServerInput) -> Result<VpnServerChange, McpFailure> {
    let name = || text(input.name.as_deref()).map(str::to_owned);
    let begin_address = || text(input.value.as_deref()).map(str::to_owned);
    let service = |service| -> Result<VpnServerChange, McpFailure> {
        Ok(VpnServerChange::Service {
            service,
            enabled: needed(input.enabled)?,
        })
    };
    Ok(match input.op.as_str() {
        "vpn_service" => service(VpnServerService::Vpn)?,
        "sstp_service" => service(VpnServerService::Sstp)?,
        "ipsec_service" => service(VpnServerService::Ipsec)?,
        "openconnect_service" => service(VpnServerService::OpenConnect)?,
        "vpn_interface" => VpnServerChange::VpnInterface { interface: name()? },
        "vpn_pool" => VpnServerChange::VpnPool {
            begin: begin_address()?,
            size: input.number,
        },
        "sstp_interface" => VpnServerChange::SstpInterface { interface: name()? },
        "sstp_pool" => VpnServerChange::SstpPool {
            begin: begin_address()?,
            size: input.number,
        },
        "wireguard_interface" => VpnServerChange::WireGuardInterface {
            interface: name()?,
            enabled: needed(input.enabled)?,
        },
        "openconnect_interface" => VpnServerChange::OpenConnectInterface { interface: name()? },
        "openconnect_pool" => VpnServerChange::OpenConnectPool {
            begin: begin_address()?,
            size: input.number,
        },
        _ => VpnServerChange::IpsecVirtualIp {
            name: name()?,
            enabled: needed(input.enabled)?,
        },
    })
}

/// Runs one VPN server write; credential operations use the secret-safe paths.
pub(super) async fn servers(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: VpnServerInput = parse(arguments)?;
    check_op(OPS, &input.op)?;
    let opened = open(
        server,
        Area::VpnServers,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    match input.op.as_str() {
        "ike_psk" => {
            let name = object(input.name.as_deref())?;
            let value = secret(input.secret)?;
            let mut changes = begin(server, &opened).await?;
            server_secrets::apply_ike_psk(&mut changes, &opened.2, name, value)
                .await
                .map_err(map_workflow)?;
            Ok(json!({ "applied": true, "unsaved": true }))
        }
        "password" => {
            let user = object(input.name.as_deref())?;
            let login = server
                .registry
                .get(opened.1.as_str())
                .map_err(|_error| McpFailure::Internal)?
                .profile
                .login;
            let planned =
                server_secrets::plan_password(&opened.2, &user, &login, secret(input.secret)?);
            apply_cli(
                server,
                &opened,
                (planned, input.confirm, server_secrets::password_request),
            )
            .await
        }
        _ => {
            let planned = vpn_servers::plan_change(&opened.2, &server_change(&input)?);
            apply_cli(
                server,
                &opened,
                (planned, input.confirm, vpn_servers::change_request),
            )
            .await
        }
    }
}
