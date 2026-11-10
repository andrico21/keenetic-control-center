//! Management recovery permissions and failure receipts over MCP.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the recovery contract"
)]
mod tests {
    use std::io::{self, Write as _};

    use kcc_app::permissions::{Permission, Role};
    use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
    use serde_json::json;

    use crate::lab::{Lab, TestResult, admin};

    /// Management recovery needs no ordinary write permission for a raw command.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn management_bracket_without_write_permission() -> TestResult {
        for mode in ["router", "extender"] {
            let mut scenario = migration::Fixture::default();
            scenario.mode = Some(mode.to_owned());
            let fake = FakeRouter::builder(Profile::default())
                .build()?
                .with_migration(scenario);
            let role = Role::new(
                "rawdes".to_owned(),
                [
                    Permission::Read,
                    Permission::RawRci,
                    Permission::Destructive,
                ],
                vec!["*".to_owned()],
            );
            let lab = Lab::start(vec![("lab-1", fake)], role).await?;
            let reply = lab.call("kcc_rci_batch", json!({"host":"lab-1","items":[{"ip":{"http":{"port":{"port":8082_u16}}}}],"confirm":true}), false).await?;
            let commands = lab
                .router("lab-1")?
                .request_log()
                .iter()
                .filter_map(|record| record.command().map(str::to_owned))
                .collect::<Vec<_>>();
            let (arm, disarm) = if mode == "router" {
                (
                    "system configuration fail-safe timer reboot 300",
                    "no system configuration fail-safe timer",
                )
            } else {
                ("system reboot 300", "no system reboot")
            };
            assert!(
                commands.iter().any(|line| line == arm)
                    && commands.iter().any(|line| line == disarm),
                "MCP rawdes {mode}: {commands:?}; {reply:?}"
            );
            assert_eq!(reply.error(), None);
            writeln!(io::stderr(), "BRACKET MCP rawdes {mode}: arm + disarm")?;
            lab.stop().await?;
        }
        Ok(())
    }

    /// Disarm refusal distinguishes an applied change from recovery failure.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn management_bracket_disarm_failure_reports_applied() -> TestResult {
        let fake = FakeRouter::builder(Profile::default())
            .faults(FaultInjection::default().fail_parse_matching("no system", 1))
            .build()?;
        let lab = Lab::start(vec![("lab-1", fake)], admin()).await?;
        let reply = lab
            .call(
                "kcc_cli_parse",
                json!({"host":"lab-1","line":"ip http port 8082","confirm":true}),
                false,
            )
            .await?;
        assert!(
            lab.router("lab-1")?
                .running_config_text()
                .contains("port 8082"),
            "management port applied"
        );
        assert_eq!(reply.error(), Some("management_applied_fail_safe_armed"));
        let state = lab
            .call("kcc_config_state", json!({"host":"lab-1"}), false)
            .await?;
        // The default fake has no reported mode, so MCP uses scheduled reboot.
        let log = lab.router("lab-1")?.request_log();
        assert!(
            log.iter()
                .any(|record| record.command() == Some("no system reboot")),
            "disarm was attempted"
        );
        assert_eq!(state.value()?.get("unsaved"), Some(&json!(true)));
        lab.stop().await
    }
}
