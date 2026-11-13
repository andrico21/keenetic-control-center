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

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use kcc_domain::{
    configuration::{self, SafetyMode, bracket::guarded},
    interfaces,
    interfaces::ManagementVerdict,
};
use kcc_rci::ObjectName;
use kcc_testkit::FaultInjection;

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

#[test]
fn unknown_falls_back_to_bridge0_only() -> TestResult {
    let bridge = ObjectName::try_from("Bridge0".to_owned())?;
    let isp = ObjectName::try_from("ISP".to_owned())?;

    assert_eq!(ManagementVerdict::Unknown.risk(&bridge), Risk::Management);
    assert_eq!(ManagementVerdict::Unknown.risk(&isp), Risk::Write);
    Ok(())
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

        let result = interfaces::apply(&mut changes, fixture.context(), &name, &operation).await?;

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
            async |bracketed, router| {
                interfaces::apply(bracketed, router, &name, &operation)
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
        assert!(failure.into_source().is_fail_safe_unarmed());
        let log = fixture.handle().request_log();
        let arm_attempt = log
            .iter()
            .position(|record| {
                record.command() == Some("system configuration fail-safe timer reboot 300")
            })
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
