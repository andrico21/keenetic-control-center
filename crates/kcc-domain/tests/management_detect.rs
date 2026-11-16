//! Management detection keeps bridge inheritance conservative without stock client evidence.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration assertions establish the public topology-classification contract"
)]

mod support;

use core::net::Ipv4Addr;

use kcc_catalog::Risk;
use kcc_domain::interfaces::{self, ManagementVerdict};
use kcc_rci::ObjectName;
use serde_json::{Value, json};

use crate::support::{Fixture, PROFILES, TestResult};

#[tokio::test]
async fn bridge0_members_stay_management_without_observed_sources() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn_with_show(
            firmware,
            topology_fixtures(Value::Array(Vec::new()), Value::Array(Vec::new())),
        )
        .await?;

        for name in ["GigabitEthernet0/1", "WifiMaster0/AccessPoint0"] {
            let object = ObjectName::try_from(name.to_owned())?;
            let verdict = interfaces::detect_management(fixture.context(), &object).await?;
            assert_eq!(verdict.risk(&object), Risk::Management, "{name}");
        }
        let bridge = ObjectName::try_from("Bridge0".to_owned())?;
        let verdict = interfaces::detect_management(fixture.context(), &bridge).await?;
        assert_eq!(verdict, ManagementVerdict::Management);

        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn bridge_verdicts_flow_to_the_named_bridge_and_its_members() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn_with_show(
            firmware,
            topology_fixtures(
                json!([
                    {"address":"192.0.2.25","interface":"Bridge0"},
                    {"address":"203.0.113.25","interface":"AccessPort8"}
                ]),
                Value::Array(Vec::new()),
            ),
        )
        .await?;
        for line in [
            "interface Bridge7 include TestPort7",
            "interface Bridge8 include AccessPort8",
        ] {
            drop(fixture.context().client.parse(line).await?);
        }

        for (name, expected_verdict, expected_risk) in [
            ("Bridge0", ManagementVerdict::Management, Risk::Management),
            (
                "GigabitEthernet0/1",
                ManagementVerdict::Management,
                Risk::Management,
            ),
            ("Bridge7", ManagementVerdict::NotManagement, Risk::Write),
            ("TestPort7", ManagementVerdict::Unknown, Risk::Write),
            ("Bridge8", ManagementVerdict::Management, Risk::Management),
            (
                "AccessPort8",
                ManagementVerdict::Management,
                Risk::Management,
            ),
        ] {
            let object = ObjectName::try_from(name.to_owned())?;
            let verdict = interfaces::detect_management(fixture.context(), &object).await?;
            assert_eq!(verdict, expected_verdict, "{name}");
            assert_eq!(verdict.risk(&object), expected_risk, "{name}");
        }

        fixture.shutdown().await?;
    }
    Ok(())
}

/// C-05: detection uses the client's pinned address, never a new lookup of the profile host.
///
/// A profile host name that does not resolve still finds the connection kcc's traffic
/// arrives on.
#[tokio::test]
async fn unresolvable_profile_host_is_classified_by_the_pinned_address() -> TestResult {
    for firmware in PROFILES {
        let peer = Ipv4Addr::LOCALHOST.to_string();
        let fixture = Fixture::spawn_with_show(
            firmware,
            [(
                "interface".to_owned(),
                json!({
                    "PPPoE0":{"id":"PPPoE0","type":"PPPoE","address":peer,"mask":"255.255.255.255"},
                    "ISP":{"id":"ISP","type":"GigabitEthernet","address":"203.0.113.2","mask":"255.255.255.0"}
                }),
            )],
        )
        .await?;
        let context = fixture.context_via("router.invalid")?;

        for (name, expected_verdict, expected_risk) in [
            ("PPPoE0", ManagementVerdict::Management, Risk::Management),
            ("ISP", ManagementVerdict::NotManagement, Risk::Write),
        ] {
            let object = ObjectName::try_from(name.to_owned())?;
            let verdict = interfaces::detect_management(&context, &object).await?;
            assert_eq!(verdict, expected_verdict, "{name}");
            assert_eq!(verdict.risk(&object), expected_risk, "{name}");
        }

        fixture.shutdown().await?;
    }
    Ok(())
}

/// C-05: an undecidable bridge or bridge member is management, not only `Bridge0`.
///
/// No observed client address means the evidence cannot decide whether it carries kcc's
/// connection.
#[tokio::test]
async fn bridges_without_evidence_fail_closed_to_management() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn_with_show(
            firmware,
            topology_fixtures(Value::Array(Vec::new()), Value::Array(Vec::new())),
        )
        .await?;
        drop(
            fixture
                .context()
                .client
                .parse("interface Bridge7 include TestPort7")
                .await?,
        );

        for name in ["Bridge7", "TestPort7", "Bridge8"] {
            let object = ObjectName::try_from(name.to_owned())?;
            let verdict = interfaces::detect_management(fixture.context(), &object).await?;
            assert_eq!(verdict.risk(&object), Risk::Management, "{name}");
        }

        fixture.shutdown().await?;
    }
    Ok(())
}

fn topology_fixtures(arp: Value, hotspot: Value) -> [(String, Value); 3] {
    [
        ("ip/arp".to_owned(), arp),
        ("ip/hotspot".to_owned(), hotspot),
        (
            "interface".to_owned(),
            json!({
                "Bridge0":{"id":"Bridge0","type":"Bridge","address":"192.0.2.1","mask":"255.255.255.0"},
                "GigabitEthernet0/1":{"id":"GigabitEthernet0/1","type":"Ethernet"},
                "WifiMaster0/AccessPoint0":{"id":"WifiMaster0/AccessPoint0","type":"AccessPoint"},
                "Bridge7":{"id":"Bridge7","type":"Bridge","address":"198.51.100.1","mask":"255.255.255.0"},
                "TestPort7":{"id":"TestPort7","type":"Ethernet"},
                "Bridge8":{"id":"Bridge8","type":"Bridge","address":"203.0.113.1","mask":"255.255.255.0"},
                "AccessPort8":{"id":"AccessPort8","type":"Ethernet"}
            }),
        ),
    ]
}
