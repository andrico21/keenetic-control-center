//! Runtime firewall risk uses all affected bindings and fails closed on discovery errors.

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions establish the management risk contract"
)]
mod tests {
    use kcc_catalog::Risk;
    use kcc_domain::firewall::{
        change, management,
        model::{Action, Direction, Protocol, Rule},
    };
    use kcc_testkit::model::Firmware;

    use crate::support::{Fixture, PROFILES, TestResult};

    /// Binding, unbinding and rules on a management-bound list share one risk.
    // NOT cancel-safe: fixture setup and router writes require fixture cleanup.
    #[tokio::test]
    async fn firewall_plans_classify_management_bindings_and_rules() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            for enabled in [true, false] {
                let plan = change::plan_bind(
                    fixture.context(),
                    "Bridge0",
                    "RuntimeAcl",
                    Direction::In,
                    enabled,
                )?
                .classify(fixture.context())
                .await;
                assert_eq!(plan.operation().risk, Risk::Management);
            }
            drop(
                fixture
                    .context()
                    .client
                    .parse("interface Bridge0 ip access-group RuntimeAcl in")
                    .await?,
            );
            let rule = Rule::new(Action::Deny, Protocol::Ip, "0.0.0.0", "0.0.0.0");
            let plan = change::plan_add_rule(fixture.context(), "RuntimeAcl", &rule)?
                .classify(fixture.context())
                .await;
            assert_eq!(
                plan.operation().risk,
                Risk::Management,
                "{}",
                fixture.handle().running_config_text()
            );
            let unrelated = change::plan_add_rule(fixture.context(), "UnboundAcl", &rule)?
                .classify(fixture.context())
                .await;
            assert_eq!(unrelated.operation().risk, Risk::Write);
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// A topology failure cannot downgrade a firewall write to ordinary risk.
    // NOT cancel-safe: fixture lifecycle owns a router task.
    #[tokio::test]
    async fn firewall_detection_failure_is_management() -> TestResult {
        let fixture = Fixture::spawn(Firmware::V5_1).await?;
        let context = fixture.context().clone();
        fixture.shutdown().await?;
        let risk = management::interfaces_risk(&context, &["ISP".to_owned()]).await;
        assert_eq!(risk, Risk::Management);
        Ok(())
    }

    /// Filtering a member of the management bridge protects the bridge's access path.
    // NOT cancel-safe: fixture writes may apply before cancellation.
    #[tokio::test]
    async fn management_bridge_member_binding_and_list_are_management() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            for line in [
                "interface Bridge0 include GigabitEthernet0/1",
                "interface GigabitEthernet0/1 ip access-group MemberAcl in",
            ] {
                drop(fixture.context().client.parse(line).await?);
            }
            let binding = change::plan_bind(
                fixture.context(),
                "GigabitEthernet0/1",
                "MemberAcl",
                Direction::In,
                true,
            )?
            .classify(fixture.context())
            .await;
            assert_eq!(
                binding.operation().risk,
                Risk::Management,
                "bridge membership carries management traffic"
            );
            let rule = Rule::new(Action::Deny, Protocol::Ip, "192.0.2.10", "198.51.100.10");
            let plan = change::plan_add_rule(fixture.context(), "MemberAcl", &rule)?
                .classify(fixture.context())
                .await;
            assert_eq!(
                plan.operation().risk,
                Risk::Management,
                "list inherits member risk"
            );
            fixture.shutdown().await?;
        }
        Ok(())
    }
}
