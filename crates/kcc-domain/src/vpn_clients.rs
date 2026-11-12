//! VPN client status, non-secret configuration, and WireGuard import.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "domain vocabulary follows router names; async reads and planners are not inline candidates"
)]

mod change;
mod import;
mod import_fields;
mod read;
mod render;
pub mod secrets;
pub mod wireguard;
#[path = "vpn_clients/wireguard/fields.rs"]
mod wireguard_fields;
#[path = "vpn_clients/wireguard/parser.rs"]
mod wireguard_parser;

use alloc::collections::BTreeMap;
use core::result::Result as CoreResult;

use kcc_app::{permissions::Permission, workflow::CliChangeRequest};
use kcc_catalog::Risk;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use self::wireguard::{WireGuardConfig, WireGuardParseError};
use crate::{
    ChangeOp, DomainDescriptor, DomainId, OperationDescriptor, Result, RouterCtx, read_show,
};

/// Supported VPN client interface type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[non_exhaustive]
pub enum VpnClientType {
    /// WireGuard tunnel.
    WireGuard,
    /// OpenVPN tunnel.
    OpenVpn,
    /// IPsec site-to-site tunnel.
    Ipsec,
    /// L2TP/IPsec tunnel.
    L2tpIpsec,
    /// PPTP tunnel.
    Pptp,
    /// SSTP tunnel.
    Sstp,
    /// ZeroTier network.
    ZeroTier,
    /// OpenConnect tunnel.
    OpenConnect,
    /// HTTP or SOCKS proxy tunnel.
    Proxy,
}

/// Secret-free WireGuard peer status.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct WireGuardPeerStatus {
    /// Peer public key.
    #[serde(rename = "public-key")]
    pub public_key: Option<String>,
    /// Endpoint arguments.
    pub endpoint: Option<Vec<String>>,
    /// Allowed-address arguments.
    #[serde(rename = "allow-ips")]
    pub allowed_ips: Option<Vec<String>>,
    /// Keepalive arguments.
    #[serde(rename = "keepalive-interval")]
    pub keepalive_interval: Option<Vec<String>>,
    /// Whether a preshared key exists, never its value.
    #[serde(rename = "preshared-key")]
    pub preshared_key_present: Option<SecretPresence>,
}

/// Secret-presence marker used by read models.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct SecretPresence {
    /// Whether the router reports a configured secret.
    pub present: bool,
}

/// Secret-free WireGuard client details.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct WireGuardStatus {
    /// Router-derived public key.
    #[serde(rename = "public-key")]
    pub public_key: Option<String>,
    /// UDP listen port.
    #[serde(rename = "listen-port")]
    pub listen_port: Option<String>,
    /// Whether a private key exists, never its value.
    #[serde(rename = "private-key")]
    pub private_key_present: Option<SecretPresence>,
    /// Peers keyed by public key.
    pub peers: BTreeMap<String, WireGuardPeerStatus>,
}

/// Non-secret OpenVPN client details.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct OpenVpnStatus {
    /// Whether routes supplied by the server are accepted.
    #[serde(rename = "accept-routes")]
    pub accept_routes: Option<bool>,
    /// Whether name servers supplied by the server are accepted.
    #[serde(rename = "name-servers")]
    pub name_servers: Option<bool>,
}

/// Non-secret IPsec client details.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct IpsecStatus {
    /// Negotiated or configured profile name.
    pub profile: Option<String>,
    /// Remote peer address.
    pub peer: Option<String>,
    /// Whether a preshared key exists, never its value.
    #[serde(rename = "preshared-key")]
    pub preshared_key_present: Option<SecretPresence>,
}

/// Non-secret PPP-derived VPN client details.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct PppVpnStatus {
    /// Remote peer.
    pub peer: Option<String>,
    /// Authentication secret presence, never its value.
    #[serde(rename = "password")]
    pub password_present: Option<SecretPresence>,
}

/// Non-secret ZeroTier client details.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ZeroTierStatus {
    /// Joined network id.
    #[serde(rename = "network-id")]
    pub network_id: Option<String>,
    /// Whether managed addresses are accepted.
    #[serde(rename = "accept-addresses")]
    pub accept_addresses: Option<bool>,
    /// Whether managed routes are accepted.
    #[serde(rename = "accept-routes")]
    pub accept_routes: Option<bool>,
}

/// Non-secret OpenConnect client details.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct OpenConnectStatus {
    /// Selected protocol.
    pub protocol: Option<String>,
    /// Authentication group.
    pub authgroup: Option<String>,
    /// Whether routes are accepted.
    #[serde(rename = "accept-routes")]
    pub accept_routes: Option<bool>,
    /// Whether addresses are accepted.
    #[serde(rename = "accept-addresses")]
    pub accept_addresses: Option<bool>,
}

/// Non-secret proxy client details.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ProxyStatus {
    /// Proxy protocol.
    pub protocol: Option<String>,
    /// Upstream host.
    pub upstream: Option<Value>,
}

/// Per-interface VPN client status from `show interface`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct VpnClientStatus {
    /// Interface id.
    pub id: String,
    /// Interface type.
    pub client_type: VpnClientType,
    /// Operational state.
    pub state: Option<String>,
    /// WireGuard details when applicable.
    pub wireguard: Option<WireGuardStatus>,
    /// OpenVPN details when applicable.
    pub openvpn: Option<OpenVpnStatus>,
    /// IPsec details when applicable.
    pub ipsec: Option<IpsecStatus>,
    /// L2TP/IPsec details when applicable.
    pub l2tp_ipsec: Option<PppVpnStatus>,
    /// PPTP details when applicable.
    pub pptp: Option<PppVpnStatus>,
    /// SSTP details when applicable.
    pub sstp: Option<PppVpnStatus>,
    /// ZeroTier details when applicable.
    pub zerotier: Option<ZeroTierStatus>,
    /// OpenConnect details when applicable.
    pub openconnect: Option<OpenConnectStatus>,
    /// Proxy details when applicable.
    pub proxy: Option<ProxyStatus>,
}

/// WireGuard ASC parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct WireGuardAsc {
    /// Ordered ASC parameter values.
    pub values: Vec<String>,
}

impl WireGuardAsc {
    /// Creates ASC parameters from values in router order (`jc`, `jmin`, `jmax`, `s1`, `s2`,
    /// `h1`..`h4`, `s3`, `s4`, `i1`..`i5`); values past the sixteenth are ignored.
    #[inline]
    #[must_use]
    pub const fn new(values: Vec<String>) -> Self {
        Self { values }
    }
}

/// One non-secret VPN client mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[expect(
    missing_docs,
    reason = "variant field names are the documented router arguments and repeating each name obscures the operation inventory"
)]
pub enum VpnClientChange {
    /// Create an interface.
    Create { name: String },
    /// Delete an interface.
    Delete { name: String },
    /// Enable or disable an interface.
    Enabled { name: String, enabled: bool },
    /// Ask the router to generate a WireGuard private key.
    GenerateWireGuardPrivateKey { name: String },
    /// Set a WireGuard listen port.
    WireGuardListenPort { name: String, port: u16 },
    /// Create a WireGuard peer by public key.
    WireGuardPeer { name: String, public_key: String },
    /// Set a WireGuard peer endpoint.
    WireGuardEndpoint {
        name: String,
        public_key: String,
        address: String,
        port: u16,
    },
    /// Add one WireGuard peer allowed-address pair.
    WireGuardAllowedIp {
        name: String,
        public_key: String,
        address: String,
        mask: String,
    },
    /// Set a WireGuard peer keepalive interval.
    WireGuardKeepalive {
        name: String,
        public_key: String,
        seconds: u16,
    },
    /// Set WireGuard ASC parameters.
    WireGuardAsc { name: String, asc: WireGuardAsc },
    /// Set a ZeroTier network id.
    ZeroTierNetwork { name: String, network_id: String },
    /// Toggle ZeroTier managed addresses.
    ZeroTierAcceptAddresses { name: String, enabled: bool },
    /// Toggle ZeroTier managed routes.
    ZeroTierAcceptRoutes { name: String, enabled: bool },
    /// Toggle OpenVPN routes supplied by the server.
    OpenVpnAcceptRoutes { name: String, enabled: bool },
    /// Toggle OpenVPN name servers supplied by the server.
    OpenVpnNameServers { name: String, enabled: bool },
    /// Set an OpenConnect protocol.
    OpenConnectProtocol { name: String, protocol: String },
    /// Toggle OpenConnect managed addresses.
    OpenConnectAcceptAddresses { name: String, enabled: bool },
    /// Toggle OpenConnect managed routes.
    OpenConnectAcceptRoutes { name: String, enabled: bool },
    /// Set a proxy protocol.
    ProxyProtocol { name: String, protocol: String },
    /// Set a proxy upstream.
    ProxyUpstream {
        name: String,
        host: String,
        port: Option<u16>,
    },
    /// Create a non-secret IKE policy.
    IkePolicy { name: String },
    /// Create a non-secret IKE proposal.
    IkeProposal { name: String },
    /// Create a non-secret IPsec profile.
    IpsecProfile { name: String },
    /// Create a non-secret IPsec transform set.
    IpsecTransformSet { name: String },
    /// Create a non-secret crypto map.
    CryptoMap { name: String },
}

/// VPN client domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::VpnClients,
    read_ops: &[OperationDescriptor {
        name: "interfaces",
        catalog_path: "show interface",
        risk: Risk::Read,
        permission: Permission::Read,
        persists_immediately: false,
    }],
    write_ops: change::WRITES,
    required_components: &[],
};

/// Reads and classifies all supported VPN client interfaces without secret values.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_clients(router: &RouterCtx) -> Result<Vec<VpnClientStatus>> {
    let value: Value = read_show(&router.client, &["show", "interface"]).await?;
    Ok(read::decode_clients(&value))
}

/// Parses a standard WireGuard configuration before any router request.
pub fn parse_wireguard_config(text: &str) -> CoreResult<WireGuardConfig, WireGuardParseError> {
    wireguard_parser::parse(text)
}

/// Plans a non-secret catalog-validated VPN client mutation.
// cancel-safe: management classification performs read-only topology requests.
pub async fn plan_change(router: &RouterCtx, change: &VpnClientChange) -> Result<ChangeOp> {
    change::plan(router, change).await
}

/// Plans imported private and peer keys through protected requests, generating a key when absent.
pub fn plan_wireguard_import(
    router: &RouterCtx,
    name: &str,
    config: &WireGuardConfig,
) -> Result<ChangeOp> {
    import::plan(router, name, config)
}

/// Converts a VPN client plan to protected workflow input.
pub fn change_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    change::request(operation)
}

/// Plans one WireGuard peer's preshared key through a protected request; the read-back
/// checks only that the router reports a key, never its value.
pub fn plan_wireguard_peer_psk(
    router: &RouterCtx,
    name: &str,
    public_key: &str,
    key: secrecy::SecretString,
) -> Result<ChangeOp> {
    import::peer_preshared(router, name, public_key, key)
}
