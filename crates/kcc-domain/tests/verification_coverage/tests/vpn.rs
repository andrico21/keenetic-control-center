//! Real VPN planner inputs for the registry guard.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kcc_domain::{
    DomainId, RouterCtx,
    vpn_clients::{
        self, VpnClientChange, WireGuardAsc,
        secrets::{self, CredentialTarget},
    },
    vpn_servers::{self, VpnServerChange, VpnServerService},
};
use secrecy::{ExposeSecret as _, SecretString};

use crate::{administration::secret, support::TestResult, tests::checked};

/// Covers client and server planners without synthetic validated requests.
pub(super) fn check(router: &RouterCtx, domain: DomainId, op: &str) -> TestResult {
    if domain == DomainId::VpnServers {
        return server(router, op);
    }
    let name = "Wireguard67".to_owned();
    let public_key = STANDARD.encode([67_u8; 32]);
    if matches!(op, "wireguard_import" | "wireguard_peer_psk") {
        let key = SecretString::from(STANDARD.encode([68_u8; 32]));
        let input = SecretString::from(format!(
            "[Interface]\nPrivateKey = {}\n[Peer]\nPublicKey = {public_key}\nPresharedKey = {}\nAllowedIPs = 192.0.2.0/24\n",
            key.expose_secret(),
            key.expose_secret()
        ));
        let parsed = vpn_clients::parse_wireguard_config(input.expose_secret())?;
        return checked(vpn_clients::change_request(
            &vpn_clients::plan_wireguard_import(router, &name, &parsed)?,
        )?);
    }
    if let Some(target) = credential(op)? {
        return checked(vpn_clients::change_request(&secrets::plan(
            router,
            &target,
            secret(),
        )?)?);
    }
    let change = match op {
        "create" => VpnClientChange::Create { name },
        "delete" => VpnClientChange::Delete { name },
        "enabled" => VpnClientChange::Enabled {
            name,
            enabled: true,
        },
        "wireguard_generate_key" => VpnClientChange::GenerateWireGuardPrivateKey { name },
        "wireguard_listen_port" => VpnClientChange::WireGuardListenPort { name, port: 51_867 },
        "wireguard_peer" => VpnClientChange::WireGuardPeer { name, public_key },
        "wireguard_endpoint" => VpnClientChange::WireGuardEndpoint {
            name,
            public_key,
            address: "192.0.2.67".to_owned(),
            port: 51_867,
        },
        "wireguard_allowed_ip" => VpnClientChange::WireGuardAllowedIp {
            name,
            public_key,
            address: "192.0.2.0".to_owned(),
            mask: "255.255.255.0".to_owned(),
        },
        "wireguard_keepalive" => VpnClientChange::WireGuardKeepalive {
            name,
            public_key,
            seconds: 25,
        },
        "wireguard_asc" => VpnClientChange::WireGuardAsc {
            name,
            asc: WireGuardAsc::new(vec!["1".to_owned(); 9]),
        },
        "zerotier_network" => VpnClientChange::ZeroTierNetwork {
            name: "ZeroTier67".to_owned(),
            network_id: "0123456789abcdef".to_owned(),
        },
        "zerotier_routes" => VpnClientChange::ZeroTierAcceptRoutes {
            name: "ZeroTier67".to_owned(),
            enabled: true,
        },
        "openvpn_routes" => VpnClientChange::OpenVpnAcceptRoutes {
            name: "OpenVPN67".to_owned(),
            enabled: true,
        },
        "openconnect_protocol" => VpnClientChange::OpenConnectProtocol {
            name: "OpenConnect67".to_owned(),
            protocol: "anyconnect".to_owned(),
        },
        "proxy_protocol" => VpnClientChange::ProxyProtocol {
            name: "Proxy67".to_owned(),
            protocol: "socks5".to_owned(),
        },
        "proxy_upstream" => VpnClientChange::ProxyUpstream {
            name: "Proxy67".to_owned(),
            host: "192.0.2.67".to_owned(),
            port: Some(1_080),
        },
        "ike_policy" => VpnClientChange::IkePolicy { name },
        "ike_proposal" => VpnClientChange::IkeProposal { name },
        "ipsec_profile" => VpnClientChange::IpsecProfile { name },
        "ipsec_transform" => VpnClientChange::IpsecTransformSet { name },
        "crypto_map" => VpnClientChange::CryptoMap { name },
        _ => return Err("uncovered VPN client operation".into()),
    };
    checked(vpn_clients::change_request(&vpn_clients::plan_change(
        router, &change,
    )?)?)
}

/// Maps credential operations to their typed target.
fn credential(op: &str) -> TestResult<Option<CredentialTarget>> {
    let name = "Coverage67".parse()?;
    Ok(match op {
        "ppp_password" => Some(CredentialTarget::Ppp("PPPoE67".parse()?)),
        "ipsec_psk" => Some(CredentialTarget::IpsecInterface(name)),
        "ike_psk" => Some(CredentialTarget::Ike(name)),
        "profile_psk" => Some(CredentialTarget::ProfilePreshared(name)),
        "profile_xauth" => Some(CredentialTarget::ProfileXauth(name)),
        _ => None,
    })
}

/// Covers every server registry entry, including credential planners.
fn server(router: &RouterCtx, op: &str) -> TestResult {
    if op == "ike_psk" {
        return checked(vpn_clients::change_request(&secrets::plan(
            router,
            &CredentialTarget::Ike("Coverage67".parse()?),
            secret(),
        )?)?);
    }
    if op == "password" {
        return checked(vpn_servers::secrets::password_request(
            &vpn_servers::secrets::plan_password(
                router,
                &"coverage67".parse()?,
                "admin",
                secret(),
            )?,
        )?);
    }
    let change = match op {
        "vpn_service" => VpnServerChange::Service {
            service: VpnServerService::Vpn,
            enabled: true,
        },
        "sstp_service" => VpnServerChange::Service {
            service: VpnServerService::Sstp,
            enabled: true,
        },
        "ipsec_service" => VpnServerChange::Service {
            service: VpnServerService::Ipsec,
            enabled: true,
        },
        "openconnect_service" => VpnServerChange::Service {
            service: VpnServerService::OpenConnect,
            enabled: true,
        },
        "vpn_interface" => VpnServerChange::VpnInterface {
            interface: "Bridge0".to_owned(),
        },
        "vpn_pool" => VpnServerChange::VpnPool {
            begin: "192.0.2.67".to_owned(),
            size: Some(5),
        },
        "sstp_interface" => VpnServerChange::SstpInterface {
            interface: "Bridge0".to_owned(),
        },
        "sstp_pool" => VpnServerChange::SstpPool {
            begin: "192.0.2.67".to_owned(),
            size: Some(5),
        },
        "wireguard_interface" => VpnServerChange::WireGuardInterface {
            interface: "Wireguard67".to_owned(),
            enabled: true,
        },
        "openconnect_interface" => VpnServerChange::OpenConnectInterface {
            interface: "Bridge0".to_owned(),
        },
        "openconnect_pool" => VpnServerChange::OpenConnectPool {
            begin: "192.0.2.67".to_owned(),
            size: Some(5),
        },
        "ipsec_virtual_ip" => VpnServerChange::IpsecVirtualIp {
            name: "Coverage67".to_owned(),
            enabled: true,
        },
        _ => return Err("uncovered VPN server operation".into()),
    };
    checked(vpn_servers::change_request(&vpn_servers::plan_change(
        router, &change,
    )?)?)
}
