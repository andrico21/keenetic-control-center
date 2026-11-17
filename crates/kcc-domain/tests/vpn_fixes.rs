//! VPN planner regressions: client delete scope, per-map virtual IP, key-free parse errors
//! and the ASC value limit.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kcc_catalog::Risk;
use kcc_domain::{
    DomainError,
    vpn_clients::{self, VpnClientChange, WireGuardAsc, wireguard::WireGuardParseError},
    vpn_servers::{self, VpnServerChange},
};
use kcc_testkit::model::Firmware;

use crate::support::{Fixture, PROFILES, TestResult};

/// D-11: the VPN client path deletes only VPN interfaces and keeps the destructive risk.
#[tokio::test]
async fn d11_vpn_client_delete_refuses_non_vpn_interfaces() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        for name in ["Bridge0", "WifiMaster0/AccessPoint0"] {
            let refused = vpn_clients::plan_change(
                fixture.context(),
                &VpnClientChange::Delete {
                    name: name.to_owned(),
                },
            )
            .await;
            assert!(
                matches!(refused, Err(DomainError::Validation { issues: _ })),
                "{name} must be refused"
            );
        }
        let mut changes = fixture.changes().await?;
        for change in [
            VpnClientChange::Create {
                name: "Wireguard7".to_owned(),
            },
            VpnClientChange::WireGuardListenPort {
                name: "Wireguard7".to_owned(),
                port: 51_820,
            },
        ] {
            let plan = vpn_clients::plan_change(fixture.context(), &change).await?;
            drop(
                changes
                    .apply_cli(vpn_clients::change_request(&plan)?)
                    .await?,
            );
        }
        let delete = vpn_clients::plan_change(
            fixture.context(),
            &VpnClientChange::Delete {
                name: "Wireguard7".to_owned(),
            },
        )
        .await?;
        assert_eq!(delete.risk, Risk::Destructive);
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// D-12: the crypto-map virtual IP is read per map name from `crypto map`.
#[tokio::test]
async fn d12_vpn_server_reads_virtual_ip_per_map_name() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let mut changes = fixture.changes().await?;
        for change in [
            VpnServerChange::IpsecMap {
                name: "VPN1".to_owned(),
            },
            VpnServerChange::IpsecVirtualIp {
                name: "VPN1".to_owned(),
                enabled: true,
            },
        ] {
            let operation = vpn_servers::plan_change(fixture.context(), &change)?;
            drop(
                changes
                    .apply_cli(vpn_servers::change_request(&operation)?)
                    .await?,
            );
        }

        let status = vpn_servers::read_servers(fixture.context()).await?;

        let value = serde_json::to_value(&status.ipsec_virtual_ip)?;
        assert_eq!(
            value.pointer("/VPN1/enable"),
            Some(&serde_json::json!(true))
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// Both formats of `error` must name neither the key nor its line text.
fn assert_key_free(error: &WireGuardParseError, stem: &str, line: &str) {
    for text in [format!("{error}"), format!("{error:?}")] {
        assert!(!text.contains(stem), "key text in {text}");
        assert!(!text.contains(line), "line text in {text}");
    }
}

/// D-16 and N8: parse errors keep only the line number, never text from the line.
#[test]
fn d16_n8_wireguard_parse_errors_carry_no_key_text() -> TestResult {
    let key = STANDARD.encode([7_u8; 32]);
    let stem = key.trim_end_matches('=');
    let public_key = STANDARD.encode([8_u8; 32]);
    let peer = format!("[Peer]\nPublicKey = {public_key}\n");
    let cases = [
        // N8: a bare key line splits at its padding into an unknown field.
        (format!("[Interface]\n{key}\n{peer}"), key.clone()),
        // A key line without any assignment is malformed.
        (format!("[Interface]\n{stem}\n{peer}"), stem.to_owned()),
        // An assignment before any section is malformed.
        (
            format!("PrivateKey = {key}\n[Interface]\n{peer}"),
            format!("PrivateKey = {key}"),
        ),
        // A key repeated in a section is a duplicate.
        (
            format!("[Interface]\nPrivateKey = {key}\nPrivateKey = {key}\n{peer}"),
            format!("PrivateKey = {key}"),
        ),
    ];
    for (text, line) in cases {
        let Err(error) = vpn_clients::parse_wireguard_config(&text) else {
            return Err("the file must not parse".into());
        };
        assert_key_free(&error, stem, &line);
    }
    Ok(())
}

/// D-17: more than 16 ASC values are refused and the documented count is accepted.
#[tokio::test]
async fn d17_wireguard_asc_refuses_more_than_sixteen_values() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let asc = |count: usize| VpnClientChange::WireGuardAsc {
            name: "Wireguard7".to_owned(),
            asc: WireGuardAsc::new(vec!["1".to_owned(); count]),
        };

        let refused = vpn_clients::plan_change(fixture.context(), &asc(17)).await;
        assert!(matches!(
            refused,
            Err(DomainError::Validation { issues: _ })
        ));
        // 4.3.9 documents nine ASC arguments, later firmware sixteen.
        let documented = if firmware == Firmware::V4_3 { 9 } else { 16 };
        let accepted = vpn_clients::plan_change(fixture.context(), &asc(documented)).await?;
        assert_eq!(accepted.commands.len(), 1);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// D-17: each ASC value is quoted in the rendered line.
#[tokio::test]
async fn d17_wireguard_asc_quotes_each_value() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        // 4.3.9 documents nine ASC arguments; later firmware adds the optional `s3`, `s4`, `i1`..`i5` group.
        let mut values = ["2", "3", "4", "5", "6", "7", "8", "9", "10"]
            .map(str::to_owned)
            .to_vec();
        let mut expected =
            r#"interface Wireguard7 wireguard asc "2" "3" "4" "5" "6" "7" "8" "9" "10""#.to_owned();
        if firmware != Firmware::V4_3 {
            values.extend(["11", "12", "<b 0x0a>", "14", "15", "16", "17"].map(str::to_owned));
            expected.push_str(r#" "11" "12" "<b 0x0a>" "14" "15" "16" "17""#);
        }
        let spaced = VpnClientChange::WireGuardAsc {
            name: "Wireguard7".to_owned(),
            asc: WireGuardAsc::new(values),
        };
        let operation = vpn_clients::plan_change(fixture.context(), &spaced)
            .await
            .map_err(|error| format!("{firmware:?}: {error:?}"))?;
        let request = vpn_clients::change_request(&operation)
            .map_err(|error| format!("{firmware:?}: {error:?}"))?;
        let line = request
            .commands
            .first()
            .ok_or("command missing")?
            .expose_for_send()?;
        assert_eq!(line.as_str(), expected);
        fixture.shutdown().await?;
    }
    Ok(())
}
