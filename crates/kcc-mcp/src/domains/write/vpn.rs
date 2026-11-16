//! `kcc_vpn_clients_write`.

use kcc_domain::vpn_clients::{
    self, VpnClientChange,
    secrets::{self as client_secrets, CredentialTarget},
};
use schemars::JsonSchema;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::Value;

use super::common::{applied, apply, apply_cli, check_op, needed, object, open, secret, text};
use crate::{
    KccMcp, McpFailure,
    domains::table::Area,
    support::{
        errors::{map_domain, map_workflow},
        route::parse,
    },
};

/// VPN client operations. `wireguard_import`, `wireguard_asc`, and `wireguard_peer_psk`
/// are not offered: they need structured or file inputs the tool does not take.
pub(super) const CLIENT_OPS: &[&str] = &[
    "create",
    "delete",
    "enabled",
    "wireguard_generate_key",
    "wireguard_listen_port",
    "wireguard_peer",
    "wireguard_endpoint",
    "wireguard_allowed_ip",
    "wireguard_keepalive",
    "zerotier_network",
    "zerotier_routes",
    "openvpn_routes",
    "openconnect_protocol",
    "proxy_protocol",
    "proxy_upstream",
    "ike_policy",
    "ike_proposal",
    "ipsec_profile",
    "ipsec_transform",
    "crypto_map",
    "ppp_password",
    "ipsec_psk",
    "ike_psk",
    "profile_psk",
    "profile_xauth",
];

/// Arguments of `kcc_vpn_clients_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct VpnInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Confirms a management operation.
    #[serde(default)]
    confirm: bool,
    /// Tunnel, crypto object, server interface, or user name.
    #[serde(default)]
    name: Option<String>,
    /// Flag for enable/accept operations.
    #[serde(default)]
    enabled: Option<bool>,
    /// Port, pool size, or keepalive seconds.
    #[serde(default)]
    number: Option<u16>,
    /// WireGuard peer public key.
    #[serde(default)]
    public_key: Option<String>,
    /// Endpoint, allowed IP, pool begin, upstream host, network id, or protocol.
    #[serde(default)]
    value: Option<String>,
    /// Mask for `wireguard_allowed_ip`.
    #[serde(default)]
    mask: Option<String>,
    /// Pre-shared key or password; never returned or logged.
    #[serde(default)]
    #[schemars(with = "Option<String>")]
    secret: Option<SecretString>,
}

/// Builds the curated VPN client change of `input`.
fn client_change(input: &VpnInput) -> Result<VpnClientChange, McpFailure> {
    let name = text(input.name.as_deref())?.to_owned();
    let value = || text(input.value.as_deref()).map(str::to_owned);
    let key = || text(input.public_key.as_deref()).map(str::to_owned);
    let flag = || needed(input.enabled);
    Ok(match input.op.as_str() {
        "create" => VpnClientChange::Create { name },
        "delete" => VpnClientChange::Delete { name },
        "enabled" => VpnClientChange::Enabled {
            name,
            enabled: flag()?,
        },
        "wireguard_generate_key" => VpnClientChange::GenerateWireGuardPrivateKey { name },
        "wireguard_listen_port" => VpnClientChange::WireGuardListenPort {
            name,
            port: needed(input.number)?,
        },
        "wireguard_peer" => VpnClientChange::WireGuardPeer {
            name,
            public_key: key()?,
        },
        "wireguard_endpoint" => VpnClientChange::WireGuardEndpoint {
            name,
            public_key: key()?,
            address: value()?,
            port: needed(input.number)?,
        },
        "wireguard_allowed_ip" => VpnClientChange::WireGuardAllowedIp {
            name,
            public_key: key()?,
            address: value()?,
            mask: text(input.mask.as_deref())?.to_owned(),
        },
        "wireguard_keepalive" => VpnClientChange::WireGuardKeepalive {
            name,
            public_key: key()?,
            seconds: needed(input.number)?,
        },
        "zerotier_network" => VpnClientChange::ZeroTierNetwork {
            name,
            network_id: value()?,
        },
        "zerotier_routes" => VpnClientChange::ZeroTierAcceptRoutes {
            name,
            enabled: flag()?,
        },
        "openvpn_routes" => VpnClientChange::OpenVpnAcceptRoutes {
            name,
            enabled: flag()?,
        },
        "openconnect_protocol" => VpnClientChange::OpenConnectProtocol {
            name,
            protocol: value()?,
        },
        "proxy_protocol" => VpnClientChange::ProxyProtocol {
            name,
            protocol: value()?,
        },
        "proxy_upstream" => VpnClientChange::ProxyUpstream {
            name,
            host: value()?,
            port: input.number,
        },
        "ike_policy" => VpnClientChange::IkePolicy { name },
        "ike_proposal" => VpnClientChange::IkeProposal { name },
        "ipsec_profile" => VpnClientChange::IpsecProfile { name },
        "ipsec_transform" => VpnClientChange::IpsecTransformSet { name },
        _ => VpnClientChange::CryptoMap { name },
    })
}

/// Runs one VPN client write; credential operations use the secret-safe executor.
// NOT cancel-safe: transmitted work may precede verification or recovery cleanup.
pub(super) async fn clients(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: VpnInput = parse(arguments)?;
    check_op(CLIENT_OPS, &input.op)?;
    let opened = open(
        server,
        Area::VpnClients,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let target = |name| match input.op.as_str() {
        "ppp_password" => Some(CredentialTarget::Ppp(name)),
        "ipsec_psk" => Some(CredentialTarget::IpsecInterface(name)),
        "ike_psk" => Some(CredentialTarget::Ike(name)),
        "profile_psk" => Some(CredentialTarget::ProfilePreshared(name)),
        "profile_xauth" => Some(CredentialTarget::ProfileXauth(name)),
        _ => None,
    };
    if let Some(credential) = target(object(input.name.as_deref())?) {
        let value = secret(input.secret)?;
        let operation =
            client_secrets::plan(&opened.2, &credential, value.clone()).map_err(map_domain)?;
        let result = apply(
            server,
            &opened,
            (&operation, input.confirm, async |changes| {
                client_secrets::apply(changes, &opened.2, &credential, value)
                    .await
                    .map_err(map_workflow)
            }),
        )
        .await?;
        return Ok(applied(result.unsaved, &result.audit));
    }
    let planned = vpn_clients::plan_change(&opened.2, &client_change(&input)?).await;
    apply_cli(
        server,
        &opened,
        (planned, input.confirm, vpn_clients::change_request),
    )
    .await
}
