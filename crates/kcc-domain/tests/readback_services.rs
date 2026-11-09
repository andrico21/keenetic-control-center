//! Service writes must reject a successful parser response without the requested state.

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "test assertions report regressions"
)]
mod tests {
    use kcc_app::workflow::WorkflowError;
    use kcc_domain::services::{self, ManagementListener, SecurityLevel};
    use kcc_testkit::FaultInjection;

    use crate::support::{Fixture, PROFILES, TestResult, toggle_service};

    /// A parser acknowledgement cannot substitute for service read-back.
    #[tokio::test]
    async fn silent_service_toggle_names_failed_field() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn_with_faults(
                firmware,
                FaultInjection::default().silent_noop_path("parse"),
            )
            .await?;
            let operation =
                services::plan_service(fixture.context(), toggle_service(firmware), true)?;
            let mut changes = fixture.changes().await?;
            let outcome = changes
                .apply_cli(services::change_request(&operation)?)
                .await;
            assert!(
                matches!(&outcome, Err(WorkflowError::VerificationFailed { field }) if field.contains("service")),
                "ignored service toggle must fail verification: {outcome:?}"
            );
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// Listener changes must compare fresh state for both faulted and working routers.
    #[tokio::test]
    async fn listener_fields_require_the_requested_values() -> TestResult {
        for firmware in PROFILES {
            for faulted in [true, false] {
                let faults = if faulted {
                    FaultInjection::default().silent_noop_path("parse")
                } else {
                    FaultInjection::default()
                };
                let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
                let operations = [
                    services::plan_port(fixture.context(), ManagementListener::Http, 8_080)?,
                    services::plan_security_level(
                        fixture.context(),
                        ManagementListener::Ssh,
                        SecurityLevel::Protected,
                    )?,
                ];
                for operation in operations {
                    let mut changes = fixture.changes().await?;
                    let result = changes
                        .apply_cli(services::change_request(&operation)?)
                        .await;
                    if faulted {
                        assert!(
                            matches!(result, Err(WorkflowError::VerificationFailed { field }) if field.starts_with("/ip/"))
                        );
                    } else {
                        assert!(result?.unsaved);
                    }
                }
                fixture.shutdown().await?;
            }
        }
        Ok(())
    }
}
