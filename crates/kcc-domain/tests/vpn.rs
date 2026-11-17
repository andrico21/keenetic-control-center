//! VPN domain integration and WireGuard parser coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kcc_domain::{
    vpn_clients::{self, VpnClientType, wireguard::WireGuardParseError},
    vpn_servers::{self, VpnServerChange, VpnServerService},
};
use secrecy::ExposeSecret;

#[test]
fn wireguard_parser_rejects_missing_peer_before_router_access() {
    let key = STANDARD.encode([0_u8; 32]);
    let text = format!("[Interface]\nPrivateKey = {key}\nListenPort = 51820\n");

    assert!(matches!(
        vpn_clients::parse_wireguard_config(&text),
        Err(error) if matches!(
            error,
            WireGuardParseError::Missing { field } if field == "[Peer]"
        )
    ));
}

#[test]
fn wireguard_parser_rejects_bad_key_and_unknown_section() {
    let bad_key = "short";
    let bad_key_text =
        format!("[Interface]\nPrivateKey = {bad_key}\n[Peer]\nPublicKey = {bad_key}\n");
    let unknown_text = "[Interface]\nListenPort = 1\n[Unknown]\nValue = x\n";

    assert!(matches!(
        vpn_clients::parse_wireguard_config(&bad_key_text),
        Err(WireGuardParseError::InvalidKey { field, line: _ }) if field == "PrivateKey"
    ));
    assert!(matches!(
        vpn_clients::parse_wireguard_config(unknown_text),
        Err(WireGuardParseError::UnknownSection { section, line: _ }) if section == "[Unknown]"
    ));
}

#[test]
fn wireguard_parser_rejects_unknown_field_and_duplicate_interface() {
    let public_key = STANDARD.encode([1_u8; 32]);
    let unknown_field = format!("[Interface]\nUnsupported = x\n[Peer]\nPublicKey = {public_key}\n");
    let duplicate_interface = format!(
        "[Interface]\nListenPort = 1\n[Interface]\nListenPort = 2\n[Peer]\nPublicKey = {public_key}\n"
    );

    assert!(matches!(
        vpn_clients::parse_wireguard_config(&unknown_field),
        Err(WireGuardParseError::UnknownField { line: 2 })
    ));
    assert!(matches!(
        vpn_clients::parse_wireguard_config(&duplicate_interface),
        Err(WireGuardParseError::Duplicate { line: 3 })
    ));
}

use crate::support::{Fixture, PROFILES, TestResult};

#[tokio::test]
async fn wireguard_import_applies_non_secret_peer_fields() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let private_key = STANDARD.encode([0_u8; 32]);
        let public_key = STANDARD.encode([1_u8; 32]);
        let preshared_key = STANDARD.encode([2_u8; 32]);
        let text = format!(
            "[Interface]\nPrivateKey = {private_key}\nListenPort = 51820\nAddress = 192.0.2.2/24\nDNS = 192.0.2.53\n\n[Peer]\nPublicKey = {public_key}\nPresharedKey = {preshared_key}\nEndpoint = 198.51.100.7:51820\nAllowedIPs = 192.0.2.0/24\nPersistentKeepalive = 25\n"
        );
        let config = vpn_clients::parse_wireguard_config(&text)?;
        assert_eq!(
            config
                .interface
                .private_key
                .as_ref()
                .map(ExposeSecret::expose_secret),
            Some(private_key.as_str())
        );
        assert!(!format!("{config:?}").contains(&private_key));
        assert!(!format!("{config:?}").contains(&preshared_key));
        let operation =
            vpn_clients::plan_wireguard_import(fixture.context(), "Wireguard7", &config).await?;
        let request = vpn_clients::change_request(&operation)?;
        let mut changes = fixture.changes().await?;

        drop(changes.apply_cli(request).await?);

        let clients = vpn_clients::read_clients(fixture.context()).await?;
        let wireguard = clients
            .iter()
            .find(|client| client.id == "Wireguard7")
            .ok_or("WireGuard client missing")?;
        assert_eq!(wireguard.client_type, VpnClientType::WireGuard);
        let status = wireguard
            .wireguard
            .as_ref()
            .ok_or("WireGuard status missing")?;
        assert_eq!(status.listen_port.as_deref(), Some("51820"));
        let peer = status
            .peers
            .get(&public_key)
            .ok_or("WireGuard peer missing")?;
        assert_eq!(
            peer.endpoint.as_deref(),
            Some(["198.51.100.7".to_owned(), "51820".to_owned()].as_slice())
        );
        assert_eq!(
            peer.allowed_ips.as_deref(),
            Some(["192.0.2.0".to_owned(), "255.255.255.0".to_owned()].as_slice())
        );
        assert_eq!(
            peer.keepalive_interval.as_deref(),
            Some(["25".to_owned()].as_slice())
        );
        let serialized = serde_json::to_string(&clients)?;
        assert!(!serialized.contains(&private_key));
        assert!(!serialized.contains(&preshared_key));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn vpn_server_services_enable_and_reads_are_secret_free() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let mut changes = fixture.changes().await?;
        for service in [
            VpnServerService::Vpn,
            VpnServerService::Sstp,
            VpnServerService::Ipsec,
            VpnServerService::OpenConnect,
        ] {
            let operation = vpn_servers::plan_change(
                fixture.context(),
                &VpnServerChange::Service {
                    service,
                    enabled: true,
                },
            )?;
            drop(
                changes
                    .apply_cli(vpn_servers::change_request(&operation)?)
                    .await?,
            );
        }

        let status = vpn_servers::read_servers(fixture.context()).await?;

        let mut services = status
            .services
            .iter()
            .filter_map(|service| service.name.as_deref())
            .collect::<Vec<_>>();
        services.sort_unstable();
        assert_eq!(
            services,
            ["ipsec", "oc-server", "sstp-server", "vpn-server"]
        );
        let serialized = serde_json::to_string(&status)?;
        assert!(!serialized.contains("password"));
        assert!(!serialized.contains("preshared"));
        assert!(!serialized.contains("private-key"));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}
