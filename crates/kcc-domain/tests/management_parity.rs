//! Curated interface-line planners retain the catalog's management classification.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration assertions establish the public planning contract"
)]

mod support;

use core::net::Ipv4Addr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kcc_catalog::{RawAuthorization, Risk};
use kcc_domain::{DomainError, segments, vpn_clients, wan, wifi};
use kcc_rci::ObjectName;

use crate::support::{Fixture, PROFILES, TestResult};

#[tokio::test]
async fn curated_interface_lines_match_catalog_management_risk() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let management = ObjectName::try_from("WifiMaster0/AccessPoint0".to_owned())?;
        let ordinary = ObjectName::try_from("WifiMaster0/AccessPoint1".to_owned())?;
        let cases = [
            (
                wifi::plan_up(fixture.context(), &management, false).await?,
                "interface WifiMaster0/AccessPoint0 down",
                Some("interface WifiMaster0/AccessPoint0 down"),
                Risk::Management,
            ),
            (
                wifi::plan_schedule(fixture.context(), &management, "Schedule0").await?,
                "interface WifiMaster0/AccessPoint0 schedule Schedule0",
                Some("interface WifiMaster0/AccessPoint0 down"),
                Risk::Management,
            ),
            (
                wifi::plan_up(fixture.context(), &ordinary, false).await?,
                "interface WifiMaster0/AccessPoint1 down",
                None,
                Risk::Write,
            ),
        ];
        for (plan, line, oracle, expected) in cases {
            if let Some(oracle_line) = oracle {
                let catalog = fixture
                    .context()
                    .catalog
                    .validate_cli(oracle_line, RawAuthorization::default())
                    .map_err(|issues| format!("{oracle_line}: {issues:?}"))?;
                assert_eq!(catalog.risk, expected, "oracle: {oracle_line}");
            }
            assert_eq!(plan.risk, expected, "curated: {line}");
        }

        let managed_segment = segment("WifiMaster0/AccessPoint0");
        let ordinary_segment = segment("WifiMaster0/AccessPoint1");
        assert_eq!(
            segments::plan_create(fixture.context(), &managed_segment)
                .await?
                .risk,
            Risk::Management
        );
        assert_eq!(
            segments::plan_delete(fixture.context(), &managed_segment)
                .await?
                .risk,
            Risk::Management
        );
        let catalog = fixture
            .context()
            .catalog
            .validate_cli(
                "interface Bridge7 include WifiMaster0/AccessPoint0",
                RawAuthorization::default(),
            )
            .map_err(|issues| format!("segment oracle: {issues:?}"))?;
        assert_eq!(catalog.risk, Risk::Management);
        assert_eq!(
            segments::plan_create(fixture.context(), &ordinary_segment)
                .await?
                .risk,
            Risk::Write
        );
        assert_eq!(
            segments::plan_delete(fixture.context(), &ordinary_segment)
                .await?
                .risk,
            Risk::Write
        );
        fixture.shutdown().await?;
    }
    Ok(())
}

fn segment(access_point: &str) -> segments::SegmentSpec {
    segments::SegmentSpec::new(
        7,
        7,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(198, 51, 100, 50),
        Vec::new(),
    )
    .with_access_point(access_point.to_owned())
}

/// Free-form VPN names must carry the risk of the interface actually rendered.
#[tokio::test]
async fn vpn_delete_and_disable_preserve_management_risk() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        for name in ["Bridge0", "WifiMaster0/AccessPoint0", "Wireguard7"] {
            for change in [
                vpn_clients::VpnClientChange::Delete {
                    name: name.to_owned(),
                },
                vpn_clients::VpnClientChange::Enabled {
                    name: name.to_owned(),
                    enabled: false,
                },
            ] {
                let deleting = matches!(change, vpn_clients::VpnClientChange::Delete { name: _ });
                let planned = vpn_clients::plan_change(fixture.context(), &change).await;
                if deleting && name != "Wireguard7" {
                    // The VPN client path removes only VPN interfaces.
                    assert!(matches!(
                        planned,
                        Err(DomainError::Validation { issues: _ })
                    ));
                    continue;
                }
                let operation = planned?;
                let request = vpn_clients::change_request(&operation)?;
                let expected = match (name, deleting) {
                    ("Wireguard7", true) => Risk::Destructive,
                    ("Wireguard7", false) => Risk::Write,
                    _ => Risk::Management,
                };
                for command in &request.commands {
                    let line = command.expose_for_send()?;
                    if expected == Risk::Management {
                        let oracle = fixture
                            .context()
                            .catalog
                            .validate_cli(line.as_str(), RawAuthorization::default())
                            .map_err(|issues| format!("catalog: {issues:?}"))?;
                        assert!(oracle.contains_management(), "oracle: {}", line.as_str());
                    }
                    assert_eq!(operation.risk, expected, "VPN: {}", line.as_str());
                }
            }
        }
        fixture.shutdown().await?;
    }
    Ok(())
}

/// WAN creation, deletion and priority use the name rendered by the request.
#[tokio::test]
async fn wan_lifecycle_and_priority_preserve_management_risk() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        for name in ["Bridge0", "WifiMaster0/AccessPoint0", "PPPoE7"] {
            let object = ObjectName::try_from(name.to_owned())?;
            for operation in [
                wan::plan_create(fixture.context(), &object).await?,
                wan::plan_delete(fixture.context(), &object).await?,
                wan::plan_priority(fixture.context(), &object, 7).await?,
            ] {
                let request = wan::change_request(&object, &operation)?;
                let expected = if name == "PPPoE7" {
                    Risk::Write
                } else {
                    Risk::Management
                };
                for command in &request.commands {
                    let line = command.expose_for_send()?;
                    if expected == Risk::Management {
                        let oracle = fixture
                            .context()
                            .catalog
                            .validate_cli(line.as_str(), RawAuthorization::default())
                            .map_err(|issues| format!("catalog: {issues:?}"))?;
                        assert!(oracle.contains_management(), "oracle: {}", line.as_str());
                    }
                    assert_eq!(operation.risk, expected, "WAN: {}", line.as_str());
                }
            }
        }
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn wireguard_import_preserves_generated_interface_risk() -> TestResult {
    let public_key = STANDARD.encode([1_u8; 32]);
    let text = format!("[Interface]\nListenPort = 51820\n[Peer]\nPublicKey = {public_key}\n");
    let config = vpn_clients::parse_wireguard_config(&text)?;
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        for (name, expected) in [
            ("Bridge0", Risk::Management),
            ("WifiMaster0/AccessPoint0", Risk::Management),
            ("Wireguard7", Risk::Write),
        ] {
            let operation =
                vpn_clients::plan_wireguard_import(fixture.context(), name, &config).await?;
            assert_eq!(operation.risk, expected, "WireGuard import: {name}");
        }
        fixture.shutdown().await?;
    }
    Ok(())
}
