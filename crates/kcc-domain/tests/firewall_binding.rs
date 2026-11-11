//! Firewall binding read-back integration coverage.

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
    firewall::{change, model::Direction},
};
use kcc_testkit::FaultInjection;

use crate::support::{Fixture, PROFILES, TestResult};

#[tokio::test]
async fn applied_binding_is_visible_to_read_back_verification() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let planned = change::plan_bind(fixture.context(), "ISP", "WebAcl", Direction::In, true)?;
        let mut changes = fixture.changes().await?;

        drop(change::apply(&mut changes, fixture.context(), &planned).await?);

        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn ignored_binding_fails_read_back_verification() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn_with_faults(
            firmware,
            FaultInjection::default().silent_noop_path("parse"),
        )
        .await?;
        let planned = change::plan_bind(fixture.context(), "ISP", "WebAcl", Direction::In, true)?;
        let mut changes = fixture.changes().await?;

        let error = match change::apply(&mut changes, fixture.context(), &planned).await {
            Ok(_result) => return Err("an ignored interface binding passed verification".into()),
            Err(found) => found,
        };

        assert!(matches!(error, DomainError::FirewallVerificationFailed));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}
