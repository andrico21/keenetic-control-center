//! Connection-policy domain integration coverage.

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
    policies::{
        change::{apply, plan},
        model::{PolicyPermit, PolicyRateLimit, PolicyRoute, RateDirection},
        read,
    },
};

use crate::support::{Fixture, PROFILES, TestResult};

#[tokio::test]
async fn fixture_policy_is_read_from_show_ip_policy() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;

        let policies = read::policies(fixture.context()).await?;

        assert!(policies.iter().any(|policy| {
            policy.name.as_deref() == Some("Policy0")
                && policy.description.as_deref() == Some("Default fixture policy")
        }));
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn every_policy_leaf_is_verified_in_a_fresh_running_configuration() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let name = "Policy9";
        let operations = [
            plan::description(fixture.context(), name, Some("uplink-policy"))?,
            plan::permit(
                fixture.context(),
                name,
                &PolicyPermit::new("ISP").with_order(7),
                true,
            )?,
            plan::multipath(fixture.context(), name, true)?,
            plan::route(
                fixture.context(),
                name,
                &PolicyRoute::network("203.0.113.0", "255.255.255.0", "ISP").with_metric(11),
                true,
            )?,
            plan::rate_limit(
                fixture.context(),
                name,
                &PolicyRateLimit::fixed("ISP", RateDirection::Input, 50_000),
                true,
            )?,
            plan::rate_limit(
                fixture.context(),
                name,
                &PolicyRateLimit::automatic("ISP", RateDirection::Output),
                true,
            )?,
            plan::standalone(fixture.context(), name, true)?,
        ];
        let mut changes = fixture.changes().await?;

        drop(
            apply::apply(
                &mut changes,
                fixture.context(),
                &plan::create(fixture.context(), name)?,
            )
            .await?,
        );
        for operation in operations {
            drop(apply::apply(&mut changes, fixture.context(), &operation).await?);
        }

        let running = fixture.handle().running_config_text();
        assert!(running.contains("ip policy Policy9"), "{running}");
        assert!(running.contains("description uplink-policy"), "{running}");
        assert!(running.contains("permit global ISP order 7"), "{running}");
        assert!(
            running.contains("route 203.0.113.0 255.255.255.0 ISP 11"),
            "{running}"
        );
        assert!(running.contains("rate-limit ISP input 50000"), "{running}");
        assert!(running.contains("rate-limit ISP output auto"), "{running}");
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn policy_leaf_removal_is_verified_as_absent() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let name = "Policy8";
        let permit = PolicyPermit::new("ISP");
        let mut changes = fixture.changes().await?;
        drop(
            apply::apply(
                &mut changes,
                fixture.context(),
                &plan::create(fixture.context(), name)?,
            )
            .await?,
        );
        drop(
            apply::apply(
                &mut changes,
                fixture.context(),
                &plan::permit(fixture.context(), name, &permit, true)?,
            )
            .await?,
        );

        drop(
            apply::apply(
                &mut changes,
                fixture.context(),
                &plan::permit(fixture.context(), name, &permit, false)?,
            )
            .await?,
        );

        assert!(
            !fixture
                .handle()
                .running_config_text()
                .contains("ip policy Policy8 permit global ISP")
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn invalid_policy_name_is_rejected_before_any_router_request() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let before = fixture.handle().request_log();

        let result = plan::create(fixture.context(), "bad name");

        assert!(matches!(result, Err(DomainError::Validation { issues: _ })));
        assert_eq!(fixture.handle().request_log(), before);
        fixture.shutdown().await?;
    }
    Ok(())
}
