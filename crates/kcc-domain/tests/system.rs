//! System domain integration coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_app::workflow::WorkflowError;
use kcc_domain::{DomainError, system};
use kcc_testkit::{
    FakeRouter, FaultInjection,
    model::{Model, Profile},
};

use crate::support::{Fixture, PROFILES, TestResult};

#[tokio::test]
async fn reads_system_models_on_both_profiles() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let version = system::read_version(fixture.context()).await?;
        let state = system::read_system(fixture.context()).await?;
        let clock = system::read_clock_date(fixture.context()).await?;
        assert_eq!(version.hw_id.as_deref(), Some("KN-1811"));
        assert_eq!(state.hostname.as_deref(), Some("host-1"));
        assert_eq!(clock.year, Some(2026));
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn hostname_silent_noop_is_detectable_by_verification_spec() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn_with_faults(
            firmware,
            FaultInjection::default().silent_noop_path("system"),
        )
        .await?;
        let operation = system::plan_hostname(fixture.context(), "changed-host")?;
        let request = system::change_request(&operation)?;
        let mut changes = fixture.changes().await?;
        let error = match changes.apply(request).await {
            Err(error) => error,
            Ok(_result) => return Err("silent no-op passed hostname read-back verification".into()),
        };
        assert!(matches!(
            error,
            WorkflowError::VerificationFailed { field } if field == "/name"
        ));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn hostname_and_timezone_writes_verify_and_reach_running_config() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let mut changes = fixture.changes().await?;

        let _hostname = changes
            .apply(system::change_request(&system::plan_hostname(
                fixture.context(),
                "changed-host",
            )?)?)
            .await?;
        let _timezone = changes
            .apply(system::change_request(&system::plan_timezone(
                fixture.context(),
                "Europe/Berlin",
            )?)?)
            .await?;

        let running = fixture.handle().running_config_text();
        assert!(
            running.contains("system hostname changed-host"),
            "{running}"
        );
        assert!(
            running.contains("system clock timezone Europe/Berlin"),
            "{running}"
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn timezone_plans_the_catalog_locality_argument() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let before = fixture.handle().request_count();
        let operation = system::plan_timezone(fixture.context(), "Europe/Berlin")?;
        let request = system::change_request(&operation)?;
        assert_eq!(request.catalog_path, "system clock timezone");
        assert_eq!(request.rci_path, ["system", "clock", "timezone"]);
        assert_eq!(
            request.body.redacted(),
            &serde_json::json!({"locality": "Europe/Berlin"})
        );
        assert_eq!(
            fixture.handle().request_count(),
            before,
            "planning sends nothing"
        );
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn factory_reset_refusal_sends_no_request() -> TestResult {
    for firmware in PROFILES {
        let profile = Profile::new(Model::Kn1811, firmware)?;
        let router = FakeRouter::builder(profile).build()?;
        assert!(matches!(
            system::confirm_factory_reset("router", "wrong"),
            Err(DomainError::ConfirmationMismatch)
        ));
        assert_eq!(router.request_count(), 0);
    }
    Ok(())
}
