//! Secret-free VPN server configuration and service control.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "domain planners and async reads are not useful inline candidates"
)]
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private conversion helpers directly mirror catalog command names"
    )
)]

mod render;
pub mod secrets;
mod verification;

use alloc::vec;

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli},
};
use kcc_catalog::{HttpMethod, Risk, ValidatedRequest};
use kcc_rci::{ConfigKind, RciBody};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
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
    /// IPsec/IKEv2 virtual-IP server configuration.
    pub ipsec_virtual_ip: Value,
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

const READS: &[OperationDescriptor] = &[OperationDescriptor {
    name: "configuration",
    catalog_path: "vpn-server",
    risk: Risk::Read,
    permission: Permission::Read,
    persists_immediately: false,
}];

const WRITES: &[OperationDescriptor] = &[
    operation("vpn_service", "service vpn-server"),
    operation("sstp_service", "service sstp-server"),
    operation("ipsec_service", "service ipsec"),
    operation("openconnect_service", "service oc-server"),
    operation("vpn_interface", "vpn-server interface"),
    operation("vpn_pool", "vpn-server pool-range"),
    operation("sstp_interface", "sstp-server interface"),
    operation("sstp_pool", "sstp-server pool-range"),
    operation("wireguard_interface", "wireguard-server interface"),
    operation("openconnect_interface", "oc-server interface"),
    operation("openconnect_pool", "oc-server pool-range"),
    operation("ipsec_virtual_ip", "crypto map virtual-ip enable"),
    operation("ike_psk", "crypto ike key"),
    OperationDescriptor {
        name: "password",
        catalog_path: "user password plain",
        risk: Risk::Management,
        permission: Permission::ManageUsers,
        persists_immediately: false,
    },
];

/// VPN server domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::VpnServers,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Reads only explicitly selected non-secret VPN server configuration fields.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_servers(router: &RouterCtx) -> Result<VpnServerStatus> {
    let tree = json!({
        "vpn-server":{"interface":{},"pool-range":{},"dns-servers":{},"mtu":{},"mru":{},"multi-login":{}},
        "sstp-server":{"interface":{},"pool-range":{},"dns-servers":{},"mtu":{},"mru":{},"multi-login":{}},
        "oc-server":{"interface":{},"pool-range":{},"dns-servers":{},"mtu":{},"multi-login":{}},
        "wireguard-server":{"interface":{}},
        "crypto":{"map":{"virtual-ip":{"enable":{},"range":{},"dns-servers":{},"interface":{}}}},
        "service":{}
    });
    let RciBody::Json(response) = router.client.show_rc(tree).await? else {
        return Err(DomainError::InvalidResponse);
    };
    let root = response
        .configuration_tree(ConfigKind::Running)
        .ok_or(DomainError::InvalidResponse)?;
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
            .pointer("/crypto/map/virtual-ip")
            .cloned()
            .unwrap_or_else(|| json!({})),
        services: root
            .get("service")
            .and_then(Value::as_array)
            .map(|services| {
                services
                    .iter()
                    .filter_map(|value| decode_opt(Some(value)))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// Plans one non-secret catalog-validated VPN server mutation.
pub fn plan_change(router: &RouterCtx, change: &VpnServerChange) -> Result<ChangeOp> {
    let (path, body, line) = render::input(change);
    let verify = verification::specs(change, path, &body);
    let mut validated = router
        .catalog
        .validate(path, HttpMethod::Post, &body)
        .map_err(|issues| DomainError::Validation { issues })?;
    validated.value = json!({"line":line,"arguments":validated.value});
    Ok(ChangeOp::new(
        vec![validated],
        verify,
        Risk::Write,
        Permission::Write,
        false,
    ))
}

/// Converts a VPN server plan to protected workflow input.
pub fn change_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let commands = operation
        .requests
        .iter()
        .map(validated_command)
        .collect::<Result<Vec<_>>>()?;
    Ok(CliChangeRequest::new(
        commands,
        operation.verify.clone(),
        operation.permission,
        json!({"domain":"vpn_servers"}),
    ))
}

fn validated_command(request: &ValidatedRequest) -> Result<ValidatedCli> {
    let line = request
        .value
        .get("line")
        .and_then(Value::as_str)
        .ok_or(DomainError::InvalidResponse)?;
    let mut validated = request.clone();
    validated.value = request
        .value
        .get("arguments")
        .cloned()
        .ok_or(DomainError::InvalidResponse)?;
    Ok(ValidatedCli::new(line.to_owned(), validated))
}

fn decode(value: Option<&Value>) -> ServerConfigStatus {
    decode_opt(value).unwrap_or_default()
}

fn decode_opt<T>(value: Option<&Value>) -> Option<T>
where
    T: DeserializeOwned,
{
    let selected = value?;
    serde_json::from_value(selected.clone()).ok()
}

const fn operation(name: &'static str, catalog_path: &'static str) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk: Risk::Write,
        permission: Permission::Write,
        persists_immediately: false,
    }
}
