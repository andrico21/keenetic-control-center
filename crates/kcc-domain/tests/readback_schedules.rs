//! Schedule writes reject acknowledged no-ops.

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
    use kcc_domain::schedules;
    use kcc_testkit::FaultInjection;

    use crate::support::{Fixture, TestResult};

    /// The F4 schedule reproduction must fail on an ignored create.
    #[tokio::test]
    async fn silent_schedule_create_names_failed_field() -> TestResult {
        let fixture =
            Fixture::spawn_with_faults(FaultInjection::default().silent_noop_path("parse")).await?;
        let operation = schedules::plan_create(fixture.context(), "f4probe")?;
        let mut changes = fixture.changes().await?;
        let outcome = changes
            .apply_cli(schedules::change_request(&operation)?)
            .await;
        assert!(
            matches!(&outcome, Err(WorkflowError::VerificationFailed { field }) if field.contains("schedule")),
            "ignored schedule must fail verification: {outcome:?}"
        );
        drop(changes);
        fixture.shutdown().await
    }

    /// An unfaulted create becomes visible through the ordinary schedule read.
    #[tokio::test]
    async fn created_schedule_is_read_back() -> TestResult {
        let fixture = Fixture::spawn().await?;
        let operation = schedules::plan_create(fixture.context(), "readback67")?;
        let mut changes = fixture.changes().await?;
        drop(
            changes
                .apply_cli(schedules::change_request(&operation)?)
                .await?,
        );
        let rows = schedules::read_schedules(fixture.context()).await?;
        assert!(
            rows.iter()
                .any(|row| row.name.as_deref() == Some("readback67"))
        );
        drop(changes);
        fixture.shutdown().await
    }
}
