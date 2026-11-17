//! DHCP domain integration coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use core::{net::Ipv4Addr, time::Duration};

use kcc_app::{audit::verify_chain, workflow::WorkflowError};
use kcc_catalog::ValidationIssue;
use kcc_domain::{DomainError, dhcp};
use kcc_testkit::FaultInjection;

use crate::support::{Fixture, PROFILES, TestResult};

#[tokio::test]
async fn static_lease_outside_bound_pool_is_refused_before_write() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let pool = test_pool();
        let mut changes = fixture.changes().await?;
        let pool_plan = dhcp::plan_pool(fixture.context(), &pool)?;
        drop(dhcp::apply(&mut changes, fixture.context(), &pool_plan).await?);
        let before = fixture.handle().request_log().len();
        let running = fixture.handle().running_config_text();

        let result = dhcp::plan_static_lease(
            fixture.context(),
            "02:00:00:00:10:aa".parse()?,
            Ipv4Addr::new(198, 51, 100, 25),
        )
        .await;

        assert!(matches!(result, Err(DomainError::StaticLeaseOutsidePool)));
        let requests = fixture.handle().request_log();
        let new_requests = requests.get(before..).ok_or("request log shortened")?;
        assert_ne!(new_requests, []);
        assert!(new_requests.iter().all(|record| matches!(
            record.path(),
            "/auth"
                | "/ci/running-config.txt"
                | "/rci/"
                | "/rci/show/ip/dhcp/bindings"
                | "/rci/show/interface"
        )));
        assert_eq!(fixture.handle().running_config_text(), running);
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn valid_static_lease_is_verified_through_running_config() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let pool = test_pool();
        let mut changes = fixture.changes().await?;
        let pool_plan = dhcp::plan_pool(fixture.context(), &pool)?;
        drop(dhcp::apply(&mut changes, fixture.context(), &pool_plan).await?);
        let mac = "02:00:00:00:10:aa";
        let address = Ipv4Addr::new(192, 0, 2, 99);

        let lease = dhcp::plan_static_lease(fixture.context(), mac.parse()?, address).await?;
        drop(dhcp::apply(&mut changes, fixture.context(), &lease).await?);

        let leases = dhcp::read_static_leases(fixture.context()).await?;
        assert!(leases.iter().any(|entry| {
            entry.mac.as_deref() == Some(mac) && entry.address.as_deref() == Some("192.0.2.99")
        }));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn pool_without_dns_or_interface_validates_and_applies() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let pool = dhcp::model::PoolConfig::new(
            "Pool24".to_owned(),
            Ipv4Addr::new(192, 0, 2, 130),
            Ipv4Addr::new(192, 0, 2, 150),
        );
        let operation = dhcp::plan_pool(fixture.context(), &pool)?;
        let mut changes = fixture.changes().await?;

        drop(dhcp::apply(&mut changes, fixture.context(), &operation).await?);

        assert!(
            fixture
                .handle()
                .running_config_text()
                .contains("ip dhcp pool Pool24")
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// C-09: a pool with two DNS servers is refused with a field error naming `dns` before any
/// router request, instead of silently sending only the first.
#[tokio::test]
async fn a_second_dns_server_is_refused_before_any_request() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let before = fixture.handle().request_count();
        let pool = test_pool().with_dns_servers(vec![
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 2),
        ]);

        let result = dhcp::plan_pool(fixture.context(), &pool);

        assert!(
            matches!(&result, Err(DomainError::Validation { issues })
                if issues == &[ValidationIssue::InvalidValue { field: "dns".to_owned() }]),
            "{firmware:?}: {result:?}"
        );
        assert_eq!(fixture.handle().request_count(), before, "nothing sent");
        fixture.shutdown().await?;
    }
    Ok(())
}

/// W3-04: an empty DNS list removes the pool's DNS server with
/// `no ip dhcp pool <name> dns-server` instead of leaving it on the router.
#[tokio::test]
async fn an_empty_dns_list_clears_the_pool_dns_server() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let mut changes = fixture.changes().await?;
        let set = dhcp::plan_pool(fixture.context(), &test_pool())?;
        drop(dhcp::apply(&mut changes, fixture.context(), &set).await?);
        assert!(
            fixture
                .handle()
                .running_config_text()
                .contains("dns-server 192.0.2.1")
        );

        let cleared = test_pool().with_dns_servers(Vec::new());
        let plan = dhcp::plan_pool(fixture.context(), &cleared)?;
        drop(dhcp::apply(&mut changes, fixture.context(), &plan).await?);

        let running = fixture.handle().running_config_text();
        assert!(
            running.contains("ip dhcp pool Pool23"),
            "{firmware:?}: {running}"
        );
        assert!(!running.contains("dns-server"), "{firmware:?}: {running}");
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// C-23: the static lease read-back runs before the workflow writes its audit entry, so a
/// failed read-back leaves no `router.change_cli` entry claiming the lease applied.
#[tokio::test]
async fn a_failed_lease_read_back_is_not_audited_as_applied() -> TestResult {
    for firmware in PROFILES {
        let planner = Fixture::spawn(firmware).await?;
        let mut setup = planner.changes().await?;
        let pool = dhcp::plan_pool(planner.context(), &test_pool())?;
        drop(dhcp::apply(&mut setup, planner.context(), &pool).await?);
        let lease = dhcp::plan_static_lease(
            planner.context(),
            "02:00:00:00:10:aa".parse()?,
            Ipv4Addr::new(192, 0, 2, 99),
        )
        .await?;
        drop(setup);
        planner.shutdown().await?;
        let faults = FaultInjection::default().fail_read_matching("\"dhcp\":{\"host\"", 1);
        let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
        let mut changes = fixture.changes().await?;

        let result = dhcp::apply(&mut changes, fixture.context(), &lease).await;

        assert!(
            matches!(result, Err(WorkflowError::Rci(_))),
            "{firmware:?}: {result:?}"
        );
        assert_eq!(fixture.audit().flush(Duration::from_secs(60)).await, 0);
        let applied = verify_chain(&fixture.state_dir())?
            .into_iter()
            .filter(|entry| entry.action.starts_with("router.change_cli"))
            .map(|entry| entry.outcome)
            .collect::<Vec<_>>();
        assert_eq!(applied, Vec::<String>::new(), "{firmware:?}");
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

fn test_pool() -> dhcp::model::PoolConfig {
    dhcp::model::PoolConfig::new(
        "Pool23".to_owned(),
        Ipv4Addr::new(192, 0, 2, 80),
        Ipv4Addr::new(192, 0, 2, 120),
    )
    .with_default_router(Ipv4Addr::new(192, 0, 2, 1))
    .with_dns_servers(vec![Ipv4Addr::new(192, 0, 2, 1)])
    .with_lease_seconds(3600)
    .with_interface("Bridge0".to_owned())
    .with_enabled(true)
}
