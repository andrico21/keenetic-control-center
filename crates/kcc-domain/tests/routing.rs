//! Routing domain integration coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_domain::{
    DomainError,
    routing::{
        change,
        model::{Ipv4Route, Ipv6Route},
        read,
    },
};
use kcc_testkit::FaultInjection;

use crate::support::{Fixture, PROFILES, TestResult};

#[tokio::test]
async fn ipv4_route_removal_decreases_the_fresh_table_by_exactly_one() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let route = Ipv4Route::network("198.51.100.0", "255.255.255.0", "192.0.2.254")
            .on_interface("ISP")
            .with_metric(7);
        let add = change::plan_add_ipv4(fixture.context(), &route)?;
        let mut changes = fixture.changes().await?;
        drop(changes.apply_cli(change::request(&add)?).await?);
        let before = read::ipv4_table(fixture.context()).await?.len();

        drop(change::remove_ipv4(&mut changes, fixture.context(), &route).await?);

        let after = read::ipv4_table(fixture.context()).await?.len();
        assert_eq!(before.checked_sub(after), Some(1));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn cleared_status_aborts_and_restores_every_removed_ipv4_route() -> TestResult {
    for firmware in PROFILES {
        let faults = FaultInjection::default().route_wipe_on_remove(true);
        let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
        let first = Ipv4Route::network("198.51.100.0", "255.255.255.0", "192.0.2.254");
        let second = Ipv4Route::network("203.0.113.0", "255.255.255.0", "192.0.2.253");
        let mut changes = fixture.changes().await?;
        for route in [&first, &second] {
            let add = change::plan_add_ipv4(fixture.context(), route)?;
            drop(changes.apply_cli(change::request(&add)?).await?);
        }
        let before = read::ipv4_table(fixture.context()).await?;

        let result = change::remove_ipv4(&mut changes, fixture.context(), &first).await;

        assert!(matches!(result, Err(DomainError::SafetyAbort)));
        let after = read::ipv4_table(fixture.context()).await?;
        assert_eq!(after, before);
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn ipv6_route_named_fields_round_trip_through_the_router() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let route = Ipv6Route::via_gateway("2001:db8:7::/64", "2001:db8::1").on_interface("ISP");
        let add = change::plan_add_ipv6(fixture.context(), &route)?;
        let mut changes = fixture.changes().await?;

        drop(changes.apply_cli(change::request(&add)?).await?);

        assert!(
            fixture
                .handle()
                .running_config_text()
                .contains("ipv6 route 2001:db8:7::/64 ISP 2001:db8::1")
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn ipv6_route_removal_decreases_the_fresh_table_by_exactly_one() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let route = Ipv6Route::via_gateway("2001:db8:7::/64", "2001:db8::1").on_interface("ISP");
        let add = change::plan_add_ipv6(fixture.context(), &route)?;
        let mut changes = fixture.changes().await?;
        drop(changes.apply_cli(change::request(&add)?).await?);
        let before = read::ipv6_table(fixture.context()).await?.len();

        drop(change::remove_ipv6(&mut changes, fixture.context(), &route).await?);

        let after = read::ipv6_table(fixture.context()).await?.len();
        assert_eq!(before.checked_sub(after), Some(1));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn cleared_status_aborts_and_restores_every_removed_ipv6_route() -> TestResult {
    for firmware in PROFILES {
        let faults = FaultInjection::default().route_wipe_on_remove(true);
        let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
        let first = Ipv6Route::via_gateway("2001:db8:7::/64", "2001:db8::1");
        let second = Ipv6Route::via_gateway("2001:db8:8::/64", "2001:db8::2");
        let mut changes = fixture.changes().await?;
        for route in [&first, &second] {
            let add = change::plan_add_ipv6(fixture.context(), route)?;
            drop(changes.apply_cli(change::request(&add)?).await?);
        }
        let before = read::ipv6_table(fixture.context()).await?;

        let result = change::remove_ipv6(&mut changes, fixture.context(), &first).await;

        assert!(matches!(result, Err(DomainError::SafetyAbort)));
        let after = read::ipv6_table(fixture.context()).await?;
        assert_eq!(after, before);
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn ipv6_route_removal_returns_count_mismatch_when_router_does_not_remove() -> TestResult {
    for firmware in PROFILES {
        let faults = FaultInjection::default().silent_noop_path("parse");
        let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
        let route = Ipv6Route::via_gateway("2001:db8:7::/64", "2001:db8::1");
        let mut changes = fixture.changes().await?;

        let result = change::remove_ipv6(&mut changes, fixture.context(), &route).await;

        assert!(matches!(result, Err(DomainError::RouteCountMismatch)));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}
