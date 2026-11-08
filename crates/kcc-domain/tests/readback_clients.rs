//! Hotspot policy writes verify their configuration independently of host MACs.

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
    use kcc_domain::clients::{self, Access, PolicySelection};
    use kcc_testkit::FaultInjection;

    use crate::support::{Fixture, TestResult};

    /// Both policy paths must fail when the parser silently ignores them.
    #[tokio::test]
    async fn silent_hotspot_policy_names_failed_field() -> TestResult {
        for interface in [None, Some("Bridge0")] {
            let fixture =
                Fixture::spawn_with_faults(FaultInjection::default().silent_noop_path("parse"))
                    .await?;
            let selection = PolicySelection::Access(Access::Deny);
            let operation = match interface {
                None => clients::plan_default_policy(fixture.context(), selection)?,
                Some(name) => clients::plan_interface_policy(fixture.context(), name, selection)?,
            };
            let mut changes = fixture.changes().await?;
            let outcome = clients::apply(&mut changes, fixture.context(), &operation).await;
            assert!(
                matches!(&outcome, Err(WorkflowError::VerificationFailed { field }) if field.contains("policy")),
                "ignored hotspot policy must fail verification: {outcome:?}"
            );
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// Both policy setters verify the mutable configuration on a working router.
    #[tokio::test]
    async fn hotspot_policies_are_visible_after_write() -> TestResult {
        let fixture = Fixture::spawn().await?;
        let operations = [
            clients::plan_default_policy(fixture.context(), PolicySelection::Access(Access::Deny))?,
            clients::plan_interface_policy(
                fixture.context(),
                "Bridge0",
                PolicySelection::Access(Access::Permit),
            )?,
        ];
        for operation in operations {
            let mut changes = fixture.changes().await?;
            let result = clients::apply(&mut changes, fixture.context(), &operation).await?;
            assert!(result.unsaved);
        }
        fixture.shutdown().await
    }
}
