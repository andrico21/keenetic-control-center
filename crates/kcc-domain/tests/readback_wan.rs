//! WAN writes reject acknowledged no-ops.

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration tests report failures through assertions"
)]
mod tests {
    use core::net::Ipv4Addr;

    use kcc_app::workflow::WorkflowError;
    use kcc_domain::{interfaces::ManagementVerdict, wan};
    use kcc_testkit::FaultInjection;

    use crate::support::{Fixture, TestResult};

    /// A created connection must exist in the fresh configuration.
    #[tokio::test]
    async fn silent_wan_create_names_failed_field() -> TestResult {
        let fixture =
            Fixture::spawn_with_faults(FaultInjection::default().silent_noop_path("parse")).await?;
        let name = "Ethernet67".parse()?;
        let operation = wan::plan_create(fixture.context(), &name)?;
        let mut changes = fixture.changes().await?;
        let outcome = changes
            .apply_cli(wan::change_request(&name, &operation)?)
            .await;
        assert!(
            matches!(&outcome, Err(WorkflowError::VerificationFailed { field }) if field.contains("interface")),
            "ignored WAN must fail verification: {outcome:?}"
        );
        drop(changes);
        fixture.shutdown().await
    }

    /// Delete, static addressing and DHCP must each detect their own ignored write.
    #[tokio::test]
    async fn silent_wan_addressing_and_delete_name_failed_field() -> TestResult {
        let fixture =
            Fixture::spawn_with_faults(FaultInjection::default().silent_noop_path("parse")).await?;
        let name = "Bridge0".parse()?;
        let operations = [
            wan::plan_delete(fixture.context(), &name)?,
            wan::plan_dhcp(fixture.context(), &name, ManagementVerdict::NotManagement)?,
            wan::plan_static_address(
                fixture.context(),
                &name,
                wan::StaticAddress::new(
                    Ipv4Addr::new(192, 0, 2, 67),
                    Ipv4Addr::new(255, 255, 255, 0),
                ),
                ManagementVerdict::NotManagement,
            )?,
        ];
        for operation in operations {
            let mut changes = fixture.changes().await?;
            let outcome = changes
                .apply_cli(wan::change_request(&name, &operation)?)
                .await;
            assert!(
                matches!(outcome, Err(WorkflowError::VerificationFailed { field }) if field.contains("interface"))
            );
        }
        fixture.shutdown().await
    }
}
