//! Routing domain integration coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_app::{
    permissions::Permission,
    workflow::{ChangeSet, CliChangeRequest, CliCommand as ValidatedCli},
};
use kcc_catalog::HttpMethod;
use kcc_domain::{
    DomainError,
    routing::{
        change,
        model::{Ipv4Route, Ipv6Route},
        read,
    },
};
use kcc_testkit::FaultInjection;
use serde_json::{Value, json};

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

/// D-08: the postcondition of a removal is the exact command's absence, so removing a
/// route that is not configured is verified, not a count mismatch.
#[tokio::test]
async fn ipv6_route_removal_is_verified_by_the_commands_absence() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let route = Ipv6Route::via_gateway("2001:db8:7::/64", "2001:db8::1");
        let mut changes = fixture.changes().await?;

        drop(change::remove_ipv6(&mut changes, fixture.context(), &route).await?);

        assert_eq!(
            route_lines(&fixture, "ipv6 route 2001:db8:7::"),
            Vec::<String>::new()
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// Adds one route spelling the model has no constructor for, through the catalog.
async fn seed(
    fixture: &Fixture,
    changes: &mut ChangeSet,
    path: &str,
    body: Value,
    line: &str,
) -> TestResult {
    let validated = fixture
        .context()
        .catalog
        .validate(path, HttpMethod::Post, &body)
        .map_err(|_issues| "route fixture invalid")?;
    let command = ValidatedCli::new(line.to_owned(), validated)?;
    drop(
        changes
            .apply_cli(CliChangeRequest::new(
                vec![command],
                Vec::new(),
                Permission::Write,
                json!({}),
            ))
            .await?,
    );
    Ok(())
}

fn route_lines(fixture: &Fixture, prefix: &str) -> Vec<String> {
    fixture
        .handle()
        .running_config_text()
        .lines()
        .filter(|line| line.starts_with(prefix))
        .map(ToOwned::to_owned)
        .collect()
}

/// D-08: removing a route is judged by the exact command's absence from the running
/// configuration, never by the routing table, which does not list inactive routes.
#[tokio::test]
async fn route_removal_does_not_consult_the_routing_table() -> TestResult {
    for firmware in PROFILES {
        let faults = FaultInjection::default()
            .fail_read_matching("show/ip/route", 8)
            .fail_read_matching("show/ipv6/route", 8);
        let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
        let v4 = Ipv4Route::network("198.51.100.0", "255.255.255.0", "192.0.2.254");
        let v6 = Ipv6Route::via_gateway("2001:db8:7::/64", "2001:db8::1");
        let mut changes = fixture.changes().await?;
        drop(
            changes
                .apply_cli(change::request(&change::plan_add_ipv4(
                    fixture.context(),
                    &v4,
                )?)?)
                .await?,
        );
        drop(
            changes
                .apply_cli(change::request(&change::plan_add_ipv6(
                    fixture.context(),
                    &v6,
                )?)?)
                .await?,
        );

        drop(change::remove_ipv4(&mut changes, fixture.context(), &v4).await?);
        drop(change::remove_ipv6(&mut changes, fixture.context(), &v6).await?);

        assert_eq!(
            route_lines(&fixture, "ip route 198.51.100.0"),
            Vec::<String>::new()
        );
        assert_eq!(
            route_lines(&fixture, "ipv6 route 2001:db8:7::"),
            Vec::<String>::new()
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// D-08: the wipe recovery restores every static route from the running configuration:
/// interface-only and default routes included, whatever their position.
#[tokio::test]
async fn wipe_recovery_restores_interface_only_and_default_ipv4_routes() -> TestResult {
    for firmware in PROFILES {
        let faults = FaultInjection::default().route_wipe_on_remove(true);
        let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
        let mut changes = fixture.changes().await?;
        seed(
            &fixture,
            &mut changes,
            "ip route",
            json!({"network":"203.0.113.0","mask":"255.255.255.0","interface":"ISP"}),
            "ip route 203.0.113.0 255.255.255.0 ISP",
        )
        .await?;
        seed(
            &fixture,
            &mut changes,
            "ip route",
            json!({"gateway":"192.0.2.1"}),
            "ip route default 192.0.2.1",
        )
        .await?;
        let first = Ipv4Route::network("198.51.100.0", "255.255.255.0", "192.0.2.254");
        let add = change::plan_add_ipv4(fixture.context(), &first)?;
        drop(changes.apply_cli(change::request(&add)?).await?);
        let before = route_lines(&fixture, "ip route");

        let result = change::remove_ipv4(&mut changes, fixture.context(), &first).await;

        assert!(
            matches!(result, Err(DomainError::SafetyAbort)),
            "{result:?}"
        );
        assert_eq!(route_lines(&fixture, "ip route"), before);
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// D-08: a route the model cannot express is reported after every other route was restored.
#[tokio::test]
async fn wipe_recovery_restores_every_ipv4_route_before_reporting_the_first_error() -> TestResult {
    for firmware in PROFILES {
        let faults = FaultInjection::default().route_wipe_on_remove(true);
        let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
        let mut changes = fixture.changes().await?;
        seed(
            &fixture,
            &mut changes,
            "ip route",
            json!({"network":"203.0.113.64","mask":"255.255.255.192","gateway":"192.0.2.7"}),
            "ip route 203.0.113.64 255.255.255.192 192.0.2.7 reject",
        )
        .await?;
        let first = Ipv4Route::network("198.51.100.0", "255.255.255.0", "192.0.2.254");
        let second = Ipv4Route::network("203.0.113.0", "255.255.255.0", "192.0.2.253");
        for route in [&first, &second] {
            let add = change::plan_add_ipv4(fixture.context(), route)?;
            drop(changes.apply_cli(change::request(&add)?).await?);
        }

        let result = change::remove_ipv4(&mut changes, fixture.context(), &first).await;

        assert!(
            matches!(result, Err(DomainError::InvalidResponse)),
            "{result:?}"
        );
        let after = route_lines(&fixture, "ip route");
        assert!(
            after.iter().any(|line| line.contains("198.51.100.0")),
            "{after:?}"
        );
        assert!(
            after.iter().any(|line| line.contains("203.0.113.0")),
            "{after:?}"
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// D-08: the IPv6 wipe recovery restores interface-only and gateway-only routes.
#[tokio::test]
async fn wipe_recovery_restores_interface_only_ipv6_routes() -> TestResult {
    for firmware in PROFILES {
        let faults = FaultInjection::default().route_wipe_on_remove(true);
        let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
        let mut changes = fixture.changes().await?;
        seed(
            &fixture,
            &mut changes,
            "ipv6 route",
            json!({"prefix":"2001:db8:9::/64","interface":"ISP"}),
            "ipv6 route 2001:db8:9::/64 ISP",
        )
        .await?;
        let first = Ipv6Route::via_gateway("2001:db8:7::/64", "2001:db8::1");
        let add = change::plan_add_ipv6(fixture.context(), &first)?;
        drop(changes.apply_cli(change::request(&add)?).await?);
        let before = route_lines(&fixture, "ipv6 route");

        let result = change::remove_ipv6(&mut changes, fixture.context(), &first).await;

        assert!(
            matches!(result, Err(DomainError::SafetyAbort)),
            "{result:?}"
        );
        assert_eq!(route_lines(&fixture, "ipv6 route"), before);
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}
