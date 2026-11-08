//! Logging configuration rejects acknowledged parser no-ops.

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
    use kcc_domain::logging;
    use kcc_testkit::FaultInjection;

    use crate::support::{Fixture, TestResult};

    /// A remote logging server must appear in fresh running configuration.
    #[tokio::test]
    async fn silent_log_server_names_failed_field() -> TestResult {
        let fixture =
            Fixture::spawn_with_faults(FaultInjection::default().silent_noop_path("parse")).await?;
        let operation = logging::plan_server(fixture.context(), "192.0.2.67", Some(514), true)?;
        let mut changes = fixture.changes().await?;
        let outcome = changes
            .apply_cli(logging::change_request(&operation)?)
            .await;
        assert!(
            matches!(&outcome, Err(WorkflowError::VerificationFailed { field }) if field.contains("log")),
            "ignored log server must fail verification: {outcome:?}"
        );
        drop(changes);
        fixture.shutdown().await
    }

    /// Working logging setters verify additions and removals.
    #[tokio::test]
    async fn logging_settings_are_read_back() -> TestResult {
        let fixture = Fixture::spawn().await?;
        for enabled in [true, false] {
            let operations = [
                logging::plan_server(fixture.context(), "192.0.2.67", Some(514), enabled)?,
                logging::plan_reduction(fixture.context(), enabled)?,
                logging::plan_suppress(fixture.context(), "Test67", enabled)?,
            ];
            for operation in operations {
                let mut changes = fixture.changes().await?;
                assert!(
                    changes
                        .apply_cli(logging::change_request(&operation)?)
                        .await?
                        .unsaved
                );
            }
        }
        fixture.shutdown().await
    }
}
