//! Closing failures preserve the recovery receipt over an actual MCP session.
extern crate alloc;

#[path = "support/lab.rs"]
mod lab;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "acceptance assertions establish the finish recovery contract"
)]
mod tests {
    use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
    use serde_json::{Value, json};

    use super::lab::{Lab, TestResult, admin};

    /// Resolves the fixture's blocked settings before applying its reviewed plan.
    async fn applied(lab: &mut Lab) -> TestResult<String> {
        let first = lab
            .call(
                "kcc_migration_plan",
                json!({"host":"lab-1", "source":"lab-src"}),
                false,
            )
            .await?;
        let value = first.value()?;
        let blocked = value.get("blocked").and_then(Value::as_array);
        let indices = |conflict: bool| {
            blocked
                .into_iter()
                .flatten()
                .filter(|item| (item.get("disposition") == Some(&json!("conflict"))) == conflict)
                .filter_map(|item| item.get("source_index").cloned())
                .collect::<Vec<_>>()
        };
        let planned = lab
            .call(
                "kcc_migration_plan",
                json!({
                    "host":"lab-1", "source":"lab-src",
                    "overwrite":indices(true), "exclude":indices(false)
                }),
                false,
            )
            .await?;
        let id = planned
            .value()?
            .get("plan_id")
            .and_then(Value::as_str)
            .ok_or("missing plan id")?
            .to_owned();
        let applied = lab
            .call(
                "kcc_migration_apply",
                json!({
                    "host":"lab-1", "plan_id":id, "confirm":true
                }),
                true,
            )
            .await?;
        assert_eq!(
            applied.value()?.pointer("/apply/verified"),
            Some(&json!(true))
        );
        assert!(
            !lab.progress_received().await.is_empty(),
            "apply reports progress"
        );
        Ok(id)
    }

    /// Exercises one closing fault through the engine and MCP error mapper.
    // NOT cancel-safe: the fixture applies and finishes a migration.
    async fn closing_failure(mode: &str, lost_reply: bool) -> TestResult {
        let command = if mode == "router" {
            "system configuration fail-safe commit"
        } else {
            "system configuration save"
        };
        let faults = if lost_reply {
            FaultInjection::default().disconnect_after_parse(command.to_owned())
        } else {
            FaultInjection::default().fail_parse_matching(command, 1)
        };
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let target = FakeRouter::builder(Profile::default())
            .faults(faults)
            .build()?
            .with_migration(scenario);
        let mut lab = Lab::start(
            vec![
                ("lab-src", FakeRouter::builder(Profile::default()).build()?),
                ("lab-1", target),
            ],
            admin(),
        )
        .await?;
        assert!(lab.tool_names().await?.contains("kcc_migration_finish"));
        let id = applied(&mut lab).await?;
        let before = lab.requests("lab-1")?;

        let reply = lab
            .call(
                "kcc_migration_finish",
                json!({
                    "host":"lab-1", "plan_id":id, "action":"commit", "confirm":true
                }),
                false,
            )
            .await?;

        assert_eq!(
            reply.error(),
            Some("management_outcome_unknown_fail_safe_armed"),
            "{mode} lost_reply={lost_reply}: {reply:?}"
        );
        assert!(lab.requests("lab-1")? > before, "finish reaches the router");
        assert_eq!(
            lab.router("lab-1")?.recovery_armed(),
            !(mode == "router" && lost_reply)
        );
        let entries = lab.audit()?;
        let failed = entries
            .iter()
            .find(|entry| entry.action == "mcp.kcc_migration_finish")
            .ok_or("missing finish audit")?;
        assert_eq!(failed.outcome, "failed");
        assert_eq!(
            failed.params_redacted.get("fail_safe_armed"),
            Some(&json!(true))
        );
        lab.stop().await?;
        Ok(())
    }

    /// A refused native commit retains the armed outcome.
    #[tokio::test]
    async fn refused_native_commit_reports_armed() -> TestResult {
        closing_failure("router", false).await
    }

    /// A lost native commit reply cannot confirm disarm, even if the router committed.
    #[tokio::test]
    async fn lost_native_commit_reports_armed() -> TestResult {
        closing_failure("router", true).await
    }

    /// A refused save leaves the scheduled reboot armed.
    #[tokio::test]
    async fn refused_scheduled_save_reports_armed() -> TestResult {
        closing_failure("extender", false).await
    }

    /// A lost save reply leaves the scheduled reboot armed.
    #[tokio::test]
    async fn lost_scheduled_save_reports_armed() -> TestResult {
        closing_failure("extender", true).await
    }
}
