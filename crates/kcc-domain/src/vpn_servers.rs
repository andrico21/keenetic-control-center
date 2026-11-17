//! Secret-free VPN server configuration and service control.

mod render;
pub mod secrets;
mod verification;

use alloc::collections::BTreeMap;

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli},
};
use kcc_catalog::Risk;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    cli_token, descriptor, planning::validate,
};

/// Service-backed VPN server kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VpnServerService {
    /// PPTP/L2TP server.
    Vpn,
    /// SSTP server.
    Sstp,
    /// IPsec/IKEv2 server.
    Ipsec,
    /// OpenConnect server.
    OpenConnect,
}

/// Secret-free server configuration projection.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ServerConfigStatus {
    /// Bound interface.
    pub interface: Option<Value>,
    /// Address-pool range.
    #[serde(rename = "pool-range")]
    pub pool_range: Option<Value>,
    /// DNS servers advertised to clients.
    #[serde(rename = "dns-servers")]
    pub dns_servers: Option<Value>,
    /// MTU.
    pub mtu: Option<Value>,
    /// MRU.
    pub mru: Option<Value>,
    /// Multiple-login policy.
    #[serde(rename = "multi-login")]
    pub multi_login: Option<Value>,
}

/// Enabled service projection.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ServiceStatus {
    /// Service name.
    pub name: Option<String>,
    /// Enabled state.
    pub enabled: Option<bool>,
}

/// Secret-free VPN server state.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[non_exhaustive]
pub struct VpnServerStatus {
    /// PPTP/L2TP server configuration.
    pub vpn: ServerConfigStatus,
    /// SSTP server configuration.
    pub sstp: ServerConfigStatus,
    /// OpenConnect server configuration.
    pub openconnect: ServerConfigStatus,
    /// WireGuard server interface bindings.
    pub wireguard_interfaces: Vec<Value>,
    /// IPsec/IKEv2 virtual-IP server configuration per crypto-map name.
    pub ipsec_virtual_ip: BTreeMap<String, Value>,
    /// Enabled VPN services.
    pub services: Vec<ServiceStatus>,
}

/// Non-secret VPN server mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[expect(
    missing_docs,
    reason = "variant field names are the documented router arguments and repeating each name obscures the operation inventory"
)]
pub enum VpnServerChange {
    /// Enable or disable a VPN server service.
    Service {
        service: VpnServerService,
        enabled: bool,
    },
    /// Bind the PPTP/L2TP server to an interface.
    VpnInterface { interface: String },
    /// Set the PPTP/L2TP client address pool.
    VpnPool { begin: String, size: Option<u16> },
    /// Set PPTP/L2TP client DNS servers.
    VpnDns {
        primary: String,
        secondary: Option<String>,
    },
    /// Bind the SSTP server to an interface.
    SstpInterface { interface: String },
    /// Set the SSTP client address pool.
    SstpPool { begin: String, size: Option<u16> },
    /// Set SSTP client DNS servers.
    SstpDns {
        primary: String,
        secondary: Option<String>,
    },
    /// Bind an interface as a WireGuard server.
    WireGuardInterface { interface: String, enabled: bool },
    /// Bind the OpenConnect server to an interface.
    OpenConnectInterface { interface: String },
    /// Set the OpenConnect client address pool.
    OpenConnectPool { begin: String, size: Option<u16> },
    /// Add an OpenConnect client route.
    OpenConnectRoute { address: String, mask: String },
    /// Set OpenConnect client DNS servers.
    OpenConnectDns {
        primary: String,
        secondary: Option<String>,
    },
    /// Create an IPsec/IKEv2 crypto map.
    IpsecMap { name: String },
    /// Enable or disable virtual-IP service on a crypto map.
    IpsecVirtualIp { name: String, enabled: bool },
    /// Set a crypto-map virtual-IP pool.
    IpsecVirtualIpPool {
        name: String,
        begin: String,
        end: Option<String>,
        size: Option<u16>,
    },
    /// Set crypto-map virtual-IP DNS servers.
    IpsecVirtualIpDns {
        name: String,
        primary: String,
        secondary: Option<String>,
    },
}

/// VPN server reads.
const READS: &[OperationDescriptor] = &[descriptor::read("configuration", "vpn-server")];

/// VPN server writes.
const WRITES: &[OperationDescriptor] = &[
    descriptor::write("vpn_service", "service vpn-server"),
    descriptor::write("sstp_service", "service sstp-server"),
    descriptor::write("ipsec_service", "service ipsec"),
    descriptor::write("openconnect_service", "service oc-server"),
    descriptor::write("vpn_interface", "vpn-server interface"),
    descriptor::write("vpn_pool", "vpn-server pool-range"),
    descriptor::write("sstp_interface", "sstp-server interface"),
    descriptor::write("sstp_pool", "sstp-server pool-range"),
    descriptor::write("wireguard_interface", "wireguard-server interface"),
    descriptor::write("openconnect_interface", "oc-server interface"),
    descriptor::write("openconnect_pool", "oc-server pool-range"),
    descriptor::write("ipsec_virtual_ip", "crypto map virtual-ip enable"),
    descriptor::write("ike_psk", "crypto ike key"),
    descriptor::operation(
        "password",
        "user password plain",
        Risk::Management,
        Permission::ManageUsers,
    ),
];

/// VPN server domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::VpnServers,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Reads only explicitly selected non-secret VPN server configuration fields.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_servers(router: &RouterCtx) -> Result<VpnServerStatus> {
    let tree = json!({
        "vpn-server":{"interface":{},"pool-range":{},"dns-servers":{},"mtu":{},"mru":{},"multi-login":{}},
        "sstp-server":{"interface":{},"pool-range":{},"dns-servers":{},"mtu":{},"mru":{},"multi-login":{}},
        "oc-server":{"interface":{},"pool-range":{},"dns-servers":{},"mtu":{},"multi-login":{}},
        "wireguard-server":{"interface":{}},
        "crypto":{"map":{}},
        "service":{}
    });
    let response = router.client.show_rc(tree).await?;
    let root = response.configuration_tree();
    Ok(VpnServerStatus {
        vpn: decode(root.get("vpn-server")),
        sstp: decode(root.get("sstp-server")),
        openconnect: decode(root.get("oc-server")),
        wireguard_interfaces: root
            .pointer("/wireguard-server/interface")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        ipsec_virtual_ip: root
            .pointer("/crypto/map")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .filter_map(|(name, map)| Some((name.clone(), map.get("virtual-ip")?.clone())))
            .collect(),
        services: root
            .get("service")
            .and_then(Value::as_array)
            .map_or_default(|services| {
                services
                    .iter()
                    .filter_map(|value| decode_opt(Some(value)))
                    .collect()
            }),
    })
}

/// Plans one non-secret catalog-validated VPN server mutation.
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), or when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_change(router: &RouterCtx, change: &VpnServerChange) -> Result<ChangeOp> {
    if let VpnServerChange::IpsecMap { name }
    | VpnServerChange::IpsecVirtualIp { name, enabled: _ }
    | VpnServerChange::IpsecVirtualIpPool {
        name,
        begin: _,
        end: _,
        size: _,
    }
    | VpnServerChange::IpsecVirtualIpDns {
        name,
        primary: _,
        secondary: _,
    } = change
    {
        cli_token::validate(name)?;
    }
    let (path, body, line) = render::input(change)?;
    let verify = verification::specs(change, path, &body);
    let validated = validate(router, path, &body)?;
    let mut operation = ChangeOp::new(Vec::new(), verify, Risk::Write, Permission::Write, false);
    operation.push(ValidatedCli::new(line, validated)?);
    Ok(operation)
}

/// Converts a VPN server plan to protected workflow input.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
#[inline]
pub fn change_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    if operation.commands.is_empty() {
        return Err(DomainError::InvalidResponse);
    }
    Ok(CliChangeRequest::new(
        operation.commands.clone(),
        operation.verify.clone(),
        operation.permission,
        json!({"domain":"vpn_servers"}),
    ))
}

/// The server settings in `value`, or the defaults when absent or undecodable.
fn decode(value: Option<&Value>) -> ServerConfigStatus {
    decode_opt(value).unwrap_or_default()
}

/// `value` decoded as `T`, or `None` when absent or undecodable.
fn decode_opt<T>(value: Option<&Value>) -> Option<T>
where
    T: DeserializeOwned,
{
    let selected = value?;
    serde_json::from_value(selected.clone()).ok()
}
