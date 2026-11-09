//! DHCP domain integration coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use core::net::Ipv4Addr;

use kcc_domain::{DomainError, dhcp};

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
            "02:00:00:00:10:aa",
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

        let lease = dhcp::plan_static_lease(fixture.context(), mac, address).await?;
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
