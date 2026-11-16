//! Services domain integration coverage.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_catalog::Risk;
use kcc_domain::{
    DomainError,
    services::{self, HttpSslSetting, ManagementListener, SecurityLevel},
};
use kcc_testkit::model::Firmware;

use crate::support::{Fixture, PROFILES, TestResult, toggle_service};

/// Service toggles preserve the Web's management classification in the shared plan.
#[tokio::test]
async fn management_service_toggles_carry_management_risk() -> TestResult {
    let fixture = Fixture::spawn(Firmware::V5_1).await?;
    for name in ["http", "ssh", "telnet"] {
        for enabled in [false, true] {
            let operation = services::plan_service(fixture.context(), name, enabled)?;
            assert_eq!(operation.risk, Risk::Management, "{name} enabled={enabled}");
        }
    }
    fixture.shutdown().await
}

#[tokio::test]
async fn service_enable_and_disable_are_visible_through_show_rc() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let service = toggle_service(firmware);
        let before = fixture.handle().request_count();
        let enable = services::plan_service(fixture.context(), service, true)?;
        let mut changes = fixture.changes().await?;
        drop(
            changes
                .apply_cli(services::change_request(&enable)?)
                .await?,
        );
        drop(changes);
        let enabled = services::read_services(fixture.context()).await?;
        assert!(enabled.iter().any(|entry| {
            entry.name.as_deref() == Some(service) && entry.enabled == Some(true)
        }));

        let disable = services::plan_service(fixture.context(), service, false)?;
        let mut disable_changes = fixture.changes().await?;
        drop(
            disable_changes
                .apply_cli(services::change_request(&disable)?)
                .await?,
        );
        drop(disable_changes);
        let disabled = services::read_services(fixture.context()).await?;
        assert!(
            !disabled
                .iter()
                .any(|entry| entry.name.as_deref() == Some(service))
        );
        assert!(fixture.handle().request_count() > before);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn management_listener_changes_are_management_risk() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let https_port = services::plan_http_ssl(fixture.context(), HttpSslSetting::Port(8_443))?;
        let ssh_level = services::plan_security_level(
            fixture.context(),
            ManagementListener::Ssh,
            SecurityLevel::Protected,
        )?;
        assert_eq!(https_port.risk, Risk::Management);
        assert_eq!(ssh_level.risk, Risk::Management);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// C-12: moving or redirecting the listener kcc uses is refused before any request.
///
/// The fake router is reached over plain HTTP on its port; the other listeners still plan
/// as management changes.
#[tokio::test]
async fn changing_the_listener_kcc_uses_is_refused_before_any_request() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let context = fixture.context();
        let before = fixture.handle().request_count();

        let moved = services::plan_port(context, ManagementListener::Http, 8_080);
        let redirected = services::plan_http_ssl(context, HttpSslSetting::Redirect(true));

        assert!(
            matches!(moved, Err(DomainError::ProtectedAccount)),
            "{moved:?}"
        );
        assert!(
            matches!(redirected, Err(DomainError::ProtectedAccount)),
            "{redirected:?}"
        );
        assert_eq!(fixture.handle().request_count(), before);
        for operation in [
            services::plan_port(context, ManagementListener::Ssh, 2_222)?,
            services::plan_http_ssl(context, HttpSslSetting::Port(8_443))?,
            services::plan_http_ssl(context, HttpSslSetting::Redirect(false))?,
        ] {
            assert_eq!(operation.risk, Risk::Management);
        }
        fixture.shutdown().await?;
    }
    Ok(())
}
