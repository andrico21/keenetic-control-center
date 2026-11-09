//! Mesh-domain integration coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_domain::{mesh, mesh::RebootError};

use crate::support::{Fixture, PROFILES, TestResult};

#[tokio::test]
async fn member_fixture_is_read_into_tolerant_model() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;

        let members = mesh::read_members(fixture.context()).await?;

        assert_eq!(members.len(), 1);
        assert_eq!(
            members.first().and_then(|member| member.id.as_deref()),
            Some("Extender0")
        );
        assert_eq!(members.first().and_then(|member| member.online), Some(true));
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn unconfirmed_member_reboot_sends_no_request() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let mut changes = fixture.changes().await?;
        let requests_before = fixture.handle().request_count();

        let result =
            mesh::reboot_member(&mut changes, fixture.context(), "Extender0", "wrong").await;

        assert!(matches!(result, Err(RebootError::ConfirmationMismatch)));
        assert_eq!(fixture.handle().request_count(), requests_before);
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn ordinary_actions_are_catalog_validated() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;

        let acquire = mesh::plan_acquire(fixture.context(), "candidate-1")?;
        let check = mesh::plan_update_check(fixture.context(), "Extender0")?;
        let start = mesh::plan_update_start(fixture.context(), "Extender0")?;

        assert_eq!(
            acquire
                .requests
                .first()
                .map(|request| request.path.as_str()),
            Some("mws acquire")
        );
        assert_eq!(
            check.requests.first().map(|request| request.path.as_str()),
            Some("mws member update check")
        );
        assert_eq!(
            start.requests.first().map(|request| request.path.as_str()),
            Some("mws member update start")
        );
        fixture.shutdown().await?;
    }
    Ok(())
}
