//! Router account writes require a fresh named account match.

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
    use kcc_domain::router_users;
    use kcc_testkit::FaultInjection;

    use crate::support::{Fixture, PROFILES, TestResult};

    /// A successful parser response alone cannot establish account creation.
    #[tokio::test]
    async fn silent_account_create_names_failed_field() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn_with_faults(
                firmware,
                FaultInjection::default().silent_noop_path("parse"),
            )
            .await?;
            let operation = router_users::plan_create(fixture.context(), "readback67", &["http"])?;
            let mut changes = fixture.changes().await?;
            let outcome = changes
                .apply_cli(router_users::change_request(&operation)?)
                .await;
            assert!(
                matches!(&outcome, Err(WorkflowError::VerificationFailed { field }) if field.contains("user")),
                "ignored account must fail verification: {outcome:?}"
            );
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// Create, tag removal and deletion all compare the named account.
    #[tokio::test]
    async fn account_and_tags_are_visible_after_write() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let operations = [
                router_users::plan_create(fixture.context(), "readback67", &["http"])?,
                router_users::plan_tag(fixture.context(), "readback67", "http", false)?,
                router_users::plan_delete(fixture.context(), "readback67", "admin")?,
            ];
            for operation in operations {
                let mut changes = fixture.changes().await?;
                assert!(
                    changes
                        .apply_cli(router_users::change_request(&operation)?)
                        .await?
                        .unsaved
                );
            }
            assert!(
                !router_users::read_users(fixture.context())
                    .await?
                    .iter()
                    .any(|row| row.name.as_deref() == Some("readback67"))
            );
            fixture.shutdown().await?;
        }
        Ok(())
    }
}
