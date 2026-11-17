//! Segments domain integration coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use core::net::Ipv4Addr;

use kcc_domain::segments;
use kcc_testkit::FaultInjection;

use crate::support::{Fixture, PROFILES, TestResult};

#[tokio::test]
async fn create_then_delete_restores_both_router_stores() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let settings = fixture.handle().settings_snapshot();
        let running = fixture.handle().running_config_text();
        let mut changes = fixture.changes().await?;

        let created = segments::create(&mut changes, fixture.context(), &segment()).await?;
        segments::delete(&mut changes, fixture.context(), created).await?;

        assert_eq!(fixture.handle().settings_snapshot(), settings);
        assert_eq!(fixture.handle().running_config_text(), running);
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn bridge_failure_rolls_vlan_and_trunks_back() -> TestResult {
    for firmware in PROFILES {
        let faults = FaultInjection::default().fail_parse_matching("interface Bridge23", 1);
        let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
        let settings = fixture.handle().settings_snapshot();
        let running = fixture.handle().running_config_text();
        let mut changes = fixture.changes().await?;

        let error = match segments::create(&mut changes, fixture.context(), &segment()).await {
            Err(error) => error,
            Ok(_created) => return Err("bridge fault did not fail segment creation".into()),
        };

        assert!(matches!(
            error,
            segments::SegmentError::StepFailed { step, source: _ } if step == "bridge"
        ));
        assert_eq!(fixture.handle().settings_snapshot(), settings);
        assert_eq!(fixture.handle().running_config_text(), running);
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

fn sent_lines(fixture: &Fixture) -> Vec<String> {
    fixture
        .handle()
        .request_log()
        .iter()
        .filter_map(|record| record.command().map(ToOwned::to_owned))
        .collect()
}

/// D-09: a step whose request was sent and whose read-back failed is rolled back too.
#[tokio::test]
async fn step_that_failed_its_read_back_is_rolled_back() -> TestResult {
    for firmware in PROFILES {
        let faults = FaultInjection::default().silent_noop_path("parse");
        let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
        let mut changes = fixture.changes().await?;

        let error = match segments::create(&mut changes, fixture.context(), &segment()).await {
            Err(error) => error,
            Ok(_created) => return Err("the unverified step did not fail the creation".into()),
        };

        assert!(matches!(
            error,
            segments::SegmentError::StepFailed { step, source: _ } if step == "vlan-subinterface"
        ));
        let lines = sent_lines(&fixture);
        let create = lines
            .iter()
            .position(|line| line == "interface Vlan23 vlan-id 23");
        let delete = lines.iter().position(|line| line == "no interface Vlan23");
        assert!(create < delete && delete.is_some(), "{lines:?}");
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// D-09: a step the router refused changed nothing, so it is not rolled back.
#[tokio::test]
async fn step_the_router_refused_is_not_rolled_back() -> TestResult {
    for firmware in PROFILES {
        let faults = FaultInjection::default().fail_parse_matching("interface Bridge23", 1);
        let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
        let mut changes = fixture.changes().await?;

        let result = segments::create(&mut changes, fixture.context(), &segment()).await;

        assert!(matches!(
            result,
            Err(segments::SegmentError::StepFailed { step, source: _ }) if step == "bridge"
        ));
        let lines = sent_lines(&fixture);
        assert!(
            lines.iter().any(|line| line == "no interface Vlan23"),
            "{lines:?}"
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.starts_with("no interface Bridge23")),
            "{lines:?}"
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

fn segment() -> segments::SegmentSpec {
    segments::SegmentSpec::new(
        23,
        23,
        Ipv4Addr::new(192, 0, 2, 129),
        Ipv4Addr::new(255, 255, 255, 192),
        Ipv4Addr::new(192, 0, 2, 130),
        Ipv4Addr::new(192, 0, 2, 180),
        vec![
            "GigabitEthernet0/0".to_owned(),
            "GigabitEthernet0/1".to_owned(),
            "GigabitEthernet0/2".to_owned(),
            "GigabitEthernet0/3".to_owned(),
            "GigabitEthernet0/4".to_owned(),
        ],
    )
}
