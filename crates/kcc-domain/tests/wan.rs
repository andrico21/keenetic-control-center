//! WAN-domain integration coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

use core::net::Ipv4Addr;
use std::fs;

use kcc_app::audit::AUDIT_FILE_NAME;
use kcc_catalog::Risk;
use kcc_domain::{interfaces::ManagementVerdict, wan, wan::StaticAddress};
use kcc_rci::ObjectName;
use kcc_testkit::leak::contains_secret;
use secrecy::SecretString;
use serde_json::json;

mod support;

use crate::support::TraceCapture;

#[test]
fn connection_decode_replaces_credentials_with_presence() -> TestResult {
    let value = json!({
        "id":"PPPoE0","type":"PPPoE","state":"up",
        "authentication":{"identity":"operator","password":{"ns3":"encoded-value"}}
    });

    let connection: wan::Connection = serde_json::from_value(value)?;
    let serialized = serde_json::to_string(&connection)?;

    assert_eq!(connection.kind, Some(wan::ConnectionKind::Pppoe));
    assert!(connection.identity_present);
    assert!(connection.password_present);
    assert!(!serialized.contains("operator"));
    assert!(!serialized.contains("encoded-value"));
    Ok(())
}

use crate::support::{Fixture, PROFILES, TestResult};

#[tokio::test]
async fn non_secret_plans_execute_through_change_set() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let name = ObjectName::try_from("Ethernet9".to_owned())?;
        let address = StaticAddress::new(
            Ipv4Addr::new(198, 51, 100, 9),
            Ipv4Addr::new(255, 255, 255, 0),
        );
        let mut changes = fixture.changes().await?;

        let create = wan::plan_create(fixture.context(), &name).await?;
        let created = changes
            .apply_cli(wan::change_request(&name, &create)?)
            .await?;
        let static_address = wan::plan_static_address(
            fixture.context(),
            &name,
            address,
            ManagementVerdict::NotManagement,
        )?;
        let configured = changes
            .apply_cli(wan::change_request(&name, &static_address)?)
            .await?;

        assert!(created.unsaved);
        assert!(configured.unsaved);
        assert!(
            fixture
                .handle()
                .running_config_text()
                .contains("ip address 198.51.100.9 255.255.255.0")
        );
        let delete = wan::plan_delete(fixture.context(), &name).await?;
        drop(
            changes
                .apply_cli(wan::change_request(&name, &delete)?)
                .await?,
        );
        assert!(!fixture.handle().running_config_text().contains("Ethernet9"));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn fake_router_reads_ipoe_without_authentication_values() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;

        let connections = wan::read_connections(fixture.context()).await?;

        let isp = connections.get("ISP").ok_or("missing ISP connection")?;
        assert_eq!(isp.kind, Some(wan::ConnectionKind::Ipoe));
        assert!(!isp.identity_present);
        assert!(!isp.password_present);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// A PPP password write leaves no plaintext in any observable output.
///
/// T-01: the secret carries `"` and `\`, which JSON, `Debug` and the CLI quoting escape, so every
/// sink is searched for each escaped form too ([`kcc_testkit::leak::contains_secret`]).
#[tokio::test]
async fn ppp_password_write_is_encoded_and_read_as_presence_only() -> TestResult {
    for firmware in PROFILES {
        let trace = TraceCapture::install();
        let fixture = Fixture::spawn(firmware).await?;
        let name = ObjectName::try_from("PPPoE9".to_owned())?;
        let mut changes = fixture.changes().await?;
        let create = wan::plan_create(fixture.context(), &name).await?;
        drop(
            changes
                .apply_cli(wan::change_request(&name, &create)?)
                .await?,
        );
        let secret = "ppp password with \"quotes\" and \\ slash";
        let operation = wan::plan_password(
            fixture.context(),
            &name,
            SecretString::from(secret.to_owned()),
        )
        .await?;
        assert!(!contains_secret(&format!("{operation:?}"), secret));
        assert!(!contains_secret(
            &serde_json::to_string(&operation.requests)?,
            secret
        ));
        let request = wan::change_request(&name, &operation)?;
        assert!(!contains_secret(&format!("{request:?}"), secret));
        assert!(!contains_secret(&serde_json::to_string(&request)?, secret));

        let result = changes.apply_cli(request).await?;
        let connections = wan::read_connections(fixture.context()).await?;

        assert!(!contains_secret(&format!("{result:?}"), secret));
        assert!(!contains_secret(&serde_json::to_string(&result)?, secret));
        assert!(!contains_secret(&format!("{connections:?}"), secret));
        assert!(!contains_secret(
            &serde_json::to_string(&connections)?,
            secret
        ));
        assert!(
            connections
                .get("PPPoE9")
                .is_some_and(|view| view.password_present)
        );
        assert!(
            fixture
                .handle()
                .running_config_text()
                .contains("password ns3")
        );
        assert!(!contains_secret(
            &fixture.handle().running_config_text(),
            secret
        ));
        assert!(!contains_secret(
            &format!("{:?}", fixture.handle().request_log()),
            secret
        ));
        let audit = fs::read(fixture.state_dir().join(AUDIT_FILE_NAME))?;
        assert!(!contains_secret(&String::from_utf8(audit)?, secret));
        assert!(!contains_secret(
            &trace.text().map_err(|error| error.to_string())?,
            secret
        ));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn ppp_password_control_character_is_refused_before_router_request() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let name = ObjectName::try_from("PPPoE9".to_owned())?;
        let before = fixture.handle().request_count();
        let secret = "bad\npassword";

        let result = wan::plan_password(
            fixture.context(),
            &name,
            SecretString::from(secret.to_owned()),
        )
        .await;

        let error = result.err().ok_or("control character was accepted")?;
        assert!(!contains_secret(&format!("{error:?}"), secret));
        assert_eq!(fixture.handle().request_count(), before);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// C-06: every WAN setting of the connection kcc's traffic runs over is a management change.
///
/// It therefore runs inside the fail-safe timer; the same settings of another connection
/// stay plain writes.
#[tokio::test]
async fn wan_settings_of_the_management_connection_are_management_changes() -> TestResult {
    for firmware in PROFILES {
        let fixture =
            Fixture::spawn_with_show(firmware, [("interface".to_owned(), wan_interfaces())])
                .await?;
        let context = fixture.context();
        let via = ObjectName::try_from("GigabitEthernet1".to_owned())?;
        for (connection, expected) in [("PPPoE0", Risk::Management), ("ISP", Risk::Write)] {
            let name = ObjectName::try_from(connection.to_owned())?;
            let secret = SecretString::from(format!("ppp-{}", 4_u8 * 7));
            let planned = [
                ("mtu", wan::plan_mtu(context, &name, 1_400).await?),
                (
                    "identity",
                    wan::plan_identity(context, &name, "subscriber").await?,
                ),
                (
                    "connect_via",
                    wan::plan_connect_via(context, &name, &via).await?,
                ),
                (
                    "default_route",
                    wan::plan_default_route(context, &name, false).await?,
                ),
                (
                    "password",
                    wan::plan_password(context, &name, secret).await?,
                ),
            ];
            for (setting, operation) in planned {
                assert_eq!(operation.risk, expected, "{connection} {setting}");
            }
        }
        fixture.shutdown().await?;
    }
    Ok(())
}

/// A PPPoE connection owning the address kcc reaches the fake router on, next to an IPoE one.
fn wan_interfaces() -> serde_json::Value {
    let peer = Ipv4Addr::LOCALHOST.to_string();
    json!({
        "PPPoE0":{"id":"PPPoE0","type":"PPPoE","address":peer,"mask":"255.255.255.255"},
        "ISP":{"id":"ISP","type":"GigabitEthernet","address":"203.0.113.2","mask":"255.255.255.0"},
        "GigabitEthernet1":{"id":"GigabitEthernet1","type":"GigabitEthernet"}
    })
}
