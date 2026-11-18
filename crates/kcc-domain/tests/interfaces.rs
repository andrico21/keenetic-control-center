//! Interface-domain integration coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::std_instead_of_alloc,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use core::net::IpAddr;
use std::collections::{BTreeMap, BTreeSet};

use kcc_app::{permissions::Permission, workflow::WorkflowError};
use kcc_catalog::Risk;
use kcc_domain::{
    DomainError,
    configuration::{self, SafetyMode, bracket::guarded},
    interfaces,
    interfaces::ManagementVerdict,
};
use kcc_rci::ObjectName;
use kcc_testkit::{FaultInjection, bracket::Recovery};

#[test]
fn direct_origin_address_classifies_isp_and_excludes_other_interfaces() -> TestResult {
    let interfaces =
        serde_json::from_value::<BTreeMap<String, interfaces::Interface>>(serde_json::json!({
            "ISP":{"id":"ISP","type":"GigabitEthernet","address":"203.0.113.11"},
            "WifiMaster1/AccessPoint0":{"id":"WifiMaster1/AccessPoint0","type":"AccessPoint"}
        }))?;
    let hosts = BTreeSet::from(["203.0.113.11".parse::<IpAddr>()?]);
    let isp = ObjectName::try_from("ISP".to_owned())?;
    let access_point = ObjectName::try_from("WifiMaster1/AccessPoint0".to_owned())?;

    let isp_verdict = interfaces::management::classify_direct(&isp, &hosts, &interfaces);
    let access_point_verdict =
        interfaces::management::classify_direct(&access_point, &hosts, &interfaces);

    assert_eq!(isp_verdict, ManagementVerdict::Management);
    assert_eq!(access_point_verdict, ManagementVerdict::NotManagement);
    Ok(())
}

/// C-05: a known owner decides names the router does not list, and its alias stays the owner.
///
/// A connection that does not exist yet carries nothing; another spelling of the owner's
/// name is still the owner; with no owner nothing is decided.
#[test]
fn a_known_owner_decides_unlisted_names_but_not_its_aliases() -> TestResult {
    let interfaces = serde_json::from_value::<BTreeMap<String, interfaces::Interface>>(
        serde_json::json!({
            "GigabitEthernet1":{"id":"GigabitEthernet1","interface-name":"ISP","address":"203.0.113.11"}
        }),
    )?;
    let owned = BTreeSet::from(["203.0.113.11".parse::<IpAddr>()?]);
    let unowned = BTreeSet::from(["198.51.100.4".parse::<IpAddr>()?]);

    for (name, hosts, expected) in [
        ("PPPoE9", &owned, ManagementVerdict::NotManagement),
        ("isp", &owned, ManagementVerdict::Management),
        ("PPPoE9", &unowned, ManagementVerdict::Unknown),
    ] {
        let object = ObjectName::try_from(name.to_owned())?;
        let verdict = interfaces::management::classify_direct(&object, hosts, &interfaces);
        assert_eq!(verdict, expected, "{name}");
    }
    Ok(())
}

/// C-04: a generic interface read drops the credential blobs `show interface` carries
/// under `authentication` and `ns3`; only which credentials are stored remains.
#[test]
fn interface_reads_drop_credential_blobs() -> TestResult {
    let [password, psk, other] = [1_u8, 2, 3].map(|index| format!("{}{index}", "QUJD".repeat(6)));
    let interfaces =
        serde_json::from_value::<BTreeMap<String, interfaces::Interface>>(serde_json::json!({
            "PPPoE0": {"id": "PPPoE0", "mtu": 1_492_u16,
                "authentication": {"identity": "user1", "password": {"ns3": password}}},
            "WifiMaster0/AccessPoint0": {"id": "WifiMaster0/AccessPoint0",
                "authentication": {"wpa-psk": {"ns3": psk}}, "extra": {"ns3": other}}
        }))?;
    let printed = serde_json::to_string(&interfaces)?;
    for blob in [&password, &psk, &other] {
        assert!(!printed.contains(blob.as_str()), "{blob} leaks: {printed}");
    }
    assert_eq!(
        interfaces
            .get("PPPoE0")
            .and_then(|interface| interface.extra.get("authentication")),
        Some(&serde_json::json!({"identity": true, "password": true})),
        "presence only"
    );
    assert_eq!(
        interfaces
            .get("PPPoE0")
            .and_then(|interface| interface.extra.get("mtu")),
        Some(&serde_json::json!(1_492_u16)),
        "other fields stay"
    );
    Ok(())
}

/// C-05: only a decided "another interface carries kcc" verdict is a plain write.
#[test]
fn only_a_decided_other_interface_is_a_plain_write() {
    for (verdict, expected) in [
        (ManagementVerdict::Management, Risk::Management),
        (ManagementVerdict::Unknown, Risk::Management),
        (ManagementVerdict::NotManagement, Risk::Write),
    ] {
        assert_eq!(verdict.risk(), expected, "{verdict:?}");
    }
}

use crate::support::{Fixture, PROFILES, TestResult};

#[tokio::test]
async fn slash_name_read_uses_root_post() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let name = ObjectName::try_from("WifiMaster1/AccessPoint0".to_owned())?;

        let interface = interfaces::read_interface(fixture.context(), &name).await?;

        assert_eq!(interface.id.as_deref(), Some(name.as_str()));
        let records = fixture.handle().request_log();
        assert!(
            records
                .iter()
                .any(|record| { record.method().as_str() == "POST" && record.path() == "/rci/" })
        );
        assert!(
            !records
                .iter()
                .any(|record| record.path().contains("/AccessPoint0"))
        );
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn management_down_plans_carry_management_risk() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        for (interface, verdict) in [
            ("Bridge0", ManagementVerdict::Unknown),
            ("ISP", ManagementVerdict::Management),
        ] {
            let name = ObjectName::try_from(interface.to_owned())?;
            let operation = interfaces::plan_down(fixture.context(), &name, verdict)?;
            assert_eq!(operation.risk, Risk::Management, "{name}");
        }
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn bridge_topology_detection_finds_management_bridge() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let name = ObjectName::try_from("Bridge0".to_owned())?;

        let verdict = interfaces::detect_management(fixture.context(), &name).await?;

        assert_eq!(verdict, ManagementVerdict::Management);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn bridge_down_applies_unsaved_without_arming_or_saving() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let startup = fixture.handle().startup_config_text();
        let name = ObjectName::try_from("Bridge0".to_owned())?;
        let operation =
            interfaces::plan_down(fixture.context(), &name, ManagementVerdict::Unknown)?;
        let mut changes = fixture.changes().await?;

        let result = interfaces::apply(&mut changes, &name, &operation).await?;

        assert!(result.unsaved);
        assert!(
            !fixture
                .handle()
                .request_log()
                .iter()
                .filter_map(|record| record.command())
                .any(|command| command.starts_with("system ")),
            "the surface owns the recovery timer"
        );
        let interface = interfaces::read_interface(fixture.context(), &name).await?;
        assert_eq!(interface.state.as_deref(), Some("down"));
        let last_change = configuration::read_last_change(fixture.context()).await?;
        assert_eq!(last_change.unsaved, Some(true));
        assert_eq!(
            last_change
                .fail_safe
                .as_ref()
                .and_then(|state| state.active),
            Some(false)
        );
        assert_eq!(fixture.handle().startup_config_text(), startup);
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn unarmed_fail_safe_refuses_the_bracketed_change_unsent() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn_with_faults(
            firmware,
            FaultInjection::default().fail_safe_arm_noop(true),
        )
        .await?;
        let name = ObjectName::try_from("Bridge0".to_owned())?;
        let operation =
            interfaces::plan_down(fixture.context(), &name, ManagementVerdict::Unknown)?;
        let mut changes = fixture.changes().await?;

        let refused = guarded(
            &mut changes,
            fixture.context(),
            SafetyMode::Router,
            Permission::Write,
            || true,
            async |bracketed, _router| {
                interfaces::apply(bracketed, &name, &operation)
                    .await
                    .map(|applied| (applied, true))
            },
        )
        .await;

        let failure = refused.err().ok_or("the unarmed bracket was refused")?;
        assert_eq!(
            failure.fate(),
            None,
            "the disarm after the failed arm closed it"
        );
        assert!(
            matches!(
                DomainError::from(failure.into_source()),
                DomainError::Workflow(WorkflowError::VerificationFailed { field })
                    if field == "/fail-safe/active"
            ),
            "the refusal names the unarmed fail-safe"
        );
        let log = fixture.handle().request_log();
        let arm_attempt = log
            .iter()
            .position(|record| record.command() == Some(Recovery::FailSafeTimer.arm()))
            .ok_or("the fail-safe arming command was not sent")?;
        let read_back = log
            .iter()
            .rposition(|record| record.path().contains("last-change"))
            .ok_or("the fail-safe state was not read back")?;
        assert!(arm_attempt < read_back, "arming precedes its read-back");
        assert_eq!(read_back + 1, log.len(), "nothing follows the read-back");
        assert!(
            !log.iter()
                .any(|record| record.command() == Some("interface Bridge0 down")),
            "the risky change was never sent"
        );
        let interface = interfaces::read_interface(fixture.context(), &name).await?;
        assert_ne!(interface.state.as_deref(), Some("down"));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}
