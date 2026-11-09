//! Structured NTP writes require fresh configuration read-back.

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration tests report failures through assertions"
)]
mod tests {
    use kcc_app::workflow::WorkflowError;
    use kcc_domain::system;
    use kcc_testkit::FaultInjection;

    use crate::support::{Fixture, PROFILES, TestResult};

    /// NTP uses the structured endpoint, so its ignored-write fault targets ntp.
    #[tokio::test]
    async fn silent_ntp_server_names_failed_field() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn_with_faults(
                firmware,
                FaultInjection::default().silent_noop_path("ntp"),
            )
            .await?;
            let operation = system::plan_ntp_server(fixture.context(), "192.0.2.67")?;
            let mut changes = fixture.changes().await?;
            let outcome = changes.apply(system::change_request(&operation)?).await;
            assert!(
                matches!(&outcome, Err(WorkflowError::VerificationFailed { field }) if field.contains("server")),
                "ignored NTP must fail verification: {outcome:?}"
            );
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// NTP settings verify on the structured write surface.
    #[tokio::test]
    async fn ntp_settings_are_read_back() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let operations = [
                system::plan_ntp_server(fixture.context(), "192.0.2.67")?,
                system::plan_ntp_master(fixture.context(), true)?,
                system::plan_ntp_sync_period(fixture.context(), 67)?,
            ];
            for operation in operations {
                let mut changes = fixture.changes().await?;
                assert!(
                    changes
                        .apply(system::change_request(&operation)?)
                        .await?
                        .unsaved
                );
            }
            fixture.shutdown().await?;
        }
        Ok(())
    }
}
