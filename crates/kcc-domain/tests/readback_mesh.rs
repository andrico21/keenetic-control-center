//! Mesh acquisition verifies fresh membership.

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
    use kcc_domain::mesh;
    use kcc_testkit::FaultInjection;

    use crate::support::{Fixture, PROFILES, TestResult};

    /// An ignored acquisition cannot report the candidate as acquired.
    #[tokio::test]
    async fn silent_mesh_acquisition_names_failed_field() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn_with_faults(
                firmware,
                FaultInjection::default().silent_noop_path("parse"),
            )
            .await?;
            let operation = mesh::plan_acquire(fixture.context(), "candidate67")?;
            let mut changes = fixture.changes().await?;
            let outcome = changes.apply_cli(mesh::change_request(&operation)?).await;
            assert!(
                matches!(&outcome, Err(WorkflowError::VerificationFailed { field }) if field == "show/mws/member"),
                "ignored acquisition must fail verification: {outcome:?}"
            );
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// Acquisition adds the candidate to a fresh membership read.
    #[tokio::test]
    async fn acquired_member_is_visible() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let operation = mesh::plan_acquire(fixture.context(), "candidate67")?;
            let mut changes = fixture.changes().await?;
            assert!(
                changes
                    .apply_cli(mesh::change_request(&operation)?)
                    .await?
                    .unsaved
            );
            assert!(
                mesh::read_members(fixture.context())
                    .await?
                    .iter()
                    .any(|member| member.id.as_deref() == Some("candidate67"))
            );
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }
}
