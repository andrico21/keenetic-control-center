//! Closing failures preserve the recovery receipt over an actual MCP session.
extern crate alloc;

#[path = "support/lab.rs"]
mod lab;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the finish recovery contract"
)]
mod tests {
    use kcc_app::permissions::{Permission, Role};
    use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
    use serde_json::{Value, json};

    use super::lab::{Lab, Reply, TestResult, admin};

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
        let retained = lab
            .call(
                "kcc_migration_report",
                json!({"host":"lab-1", "plan_id":id}),
                false,
            )
            .await?;
        assert_eq!(
            retained.value()?.pointer("/apply/finished"),
            Some(&json!(false))
        );
        if !lost_reply {
            let retry = lab
                .call(
                    "kcc_migration_finish",
                    json!({
                        "host":"lab-1", "plan_id":id, "action":"commit", "confirm":true
                    }),
                    false,
                )
                .await?;
            assert_eq!(
                retry.value()?.pointer("/apply/finished"),
                Some(&json!(true))
            );
        }
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

    /// A refused rollback remains retryable and reports the armed timer.
    #[tokio::test]
    async fn refused_rollback_reports_armed() -> TestResult {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        let target = FakeRouter::builder(Profile::default())
            .faults(FaultInjection::default().fail_parse_matching("fail-safe rollback", 1))
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
        let id = applied(&mut lab).await?;

        let reply = lab
            .call(
                "kcc_migration_finish",
                json!({"host":"lab-1", "plan_id":id, "action":"rollback", "confirm":true}),
                false,
            )
            .await?;

        assert_eq!(
            reply.error(),
            Some("management_outcome_unknown_fail_safe_armed"),
            "{reply:?}"
        );
        assert!(lab.router("lab-1")?.recovery_armed());
        let retained = lab
            .call(
                "kcc_migration_report",
                json!({"host":"lab-1", "plan_id":id}),
                false,
            )
            .await?;
        assert_eq!(
            retained.value()?.pointer("/apply/finished"),
            Some(&json!(false))
        );
        lab.stop().await
    }

    /// C-15: a router-mode commit sends the native commit alone, which saves.
    ///
    /// A router that would refuse a second save finishes the migration as committed.
    #[tokio::test]
    async fn native_commit_sends_no_second_save() -> TestResult {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        let target = FakeRouter::builder(Profile::default())
            .faults(FaultInjection::default().fail_parse_matching("system configuration save", 1))
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
        let id = applied(&mut lab).await?;

        let reply = lab
            .call(
                "kcc_migration_finish",
                json!({"host":"lab-1", "plan_id":id, "action":"commit", "confirm":true}),
                false,
            )
            .await?;

        assert_eq!(reply.error(), None, "{reply:?}");
        let retained = lab
            .call(
                "kcc_migration_report",
                json!({"host":"lab-1", "plan_id":id}),
                false,
            )
            .await?;
        assert_eq!(
            retained.value()?.pointer("/apply/finished"),
            Some(&json!(true))
        );
        lab.stop().await
    }

    /// A role reduced after apply cannot send commit and keeps the armed migration.
    #[tokio::test]
    async fn local_save_refusal_reports_commit_not_sent_and_keeps_retryable_state() -> TestResult {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        let target = FakeRouter::builder(Profile::default())
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
        let id = applied(&mut lab).await?;
        lab.roles.replace(vec![Role::new(
            "admin".to_owned(),
            Permission::ALL
                .into_iter()
                .filter(|permission| *permission != Permission::Save),
            vec!["*".to_owned()],
        )]);
        let before = lab.requests("lab-1")?;

        let reply = lab
            .call(
                "kcc_migration_finish",
                json!({"host":"lab-1", "plan_id":id, "action":"commit", "confirm":true}),
                false,
            )
            .await?;

        assert_eq!(
            reply.error(),
            Some("management_not_committed_fail_safe_armed")
        );
        assert_eq!(lab.requests("lab-1")?, before, "commit was not sent");
        assert!(lab.router("lab-1")?.recovery_armed());
        let failed = lab
            .audit()?
            .into_iter()
            .find(|entry| entry.action == "mcp.kcc_migration_finish")
            .ok_or("missing finish audit")?;
        assert_eq!(
            failed.params_redacted.get("fail_safe_armed"),
            Some(&json!(true))
        );
        let retained = lab
            .call(
                "kcc_migration_report",
                json!({"host":"lab-1", "plan_id":id}),
                false,
            )
            .await?;
        assert_eq!(
            retained.value()?.pointer("/apply/finished"),
            Some(&json!(false))
        );
        lab.stop().await
    }

    /// Drift leaves the migration open, its timer reported armed, for a rollback.
    #[tokio::test]
    async fn drifted_commit_remains_retryable_by_rollback() -> TestResult {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        let target = FakeRouter::builder(Profile::default())
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
        let id = applied(&mut lab).await?;
        drop(
            lab.registry
                .client("lab-1")
                .await?
                .parse("interface Bridge0 description out-of-band")
                .await?,
        );

        let drifted = lab
            .call(
                "kcc_migration_finish",
                json!({"host":"lab-1", "plan_id":id, "action":"commit", "confirm":true}),
                false,
            )
            .await?;
        assert_eq!(
            drifted.error(),
            Some("management_outcome_unknown_fail_safe_armed"),
            "{drifted:?}"
        );
        let retained = lab
            .call(
                "kcc_migration_report",
                json!({"host":"lab-1", "plan_id":id}),
                false,
            )
            .await?;
        assert_eq!(
            retained.value()?.pointer("/apply/finished"),
            Some(&json!(false))
        );

        let rollback = lab
            .call(
                "kcc_migration_finish",
                json!({"host":"lab-1", "plan_id":id, "action":"rollback", "confirm":true}),
                false,
            )
            .await?;
        assert_eq!(
            rollback.value()?.pointer("/apply/finished"),
            Some(&json!(true))
        );
        lab.stop().await
    }

    /// Applies onto an extender whose router answers `fail_after` requests, then rolls back.
    // NOT cancel-safe: the fixture applies and reboots a migration target.
    async fn extender_rollback(fail_after: Option<u64>) -> TestResult<(Lab, String, Reply)> {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("extender".to_owned());
        let faults = fail_after.map_or_else(FaultInjection::default, |count| {
            FaultInjection::default().fail_after_requests(count)
        });
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
        let id = applied(&mut lab).await?;
        let reply = lab
            .call(
                "kcc_migration_finish",
                json!({"host":"lab-1", "plan_id":id, "action":"rollback", "confirm":true}),
                false,
            )
            .await?;
        Ok((lab, id, reply))
    }

    /// A reboot the extender accepts before going silent closes the migration: the code
    /// says the router is restarting, and a second finish sends nothing.
    // NOT cancel-safe: both fixtures apply and reboot a migration target.
    #[tokio::test(start_paused = true)]
    async fn silent_extender_rollback_reports_restarting_and_closes() -> TestResult {
        let (baseline, _id, rolled) = extender_rollback(None).await?;
        assert_eq!(
            rolled.value()?.pointer("/apply/finished"),
            Some(&json!(true))
        );
        let reboot = baseline
            .router("lab-1")?
            .request_log()
            .iter()
            .position(|record| record.command() == Some("system reboot"))
            .and_then(|index| u64::try_from(index).ok())
            .ok_or("the baseline rollback sends no reboot")?;
        baseline.stop().await?;

        let (lab, id, reply) = extender_rollback(Some(reboot.saturating_add(1))).await?;
        assert_eq!(
            reply.error(),
            Some("migration_rollback_restarting"),
            "{reply:?}"
        );
        let silent = lab.requests("lab-1")?;
        let again = lab
            .call(
                "kcc_migration_finish",
                json!({"host":"lab-1", "plan_id":id, "action":"rollback", "confirm":true}),
                false,
            )
            .await?;
        assert_eq!(again.error(), Some("conflict"), "{again:?}");
        assert_eq!(lab.requests("lab-1")?, silent, "no second reboot is sent");
        let reboots = lab
            .router("lab-1")?
            .request_log()
            .iter()
            .filter(|record| record.command() == Some("system reboot"))
            .count();
        assert_eq!(reboots, 1);
        lab.stop().await
    }
}
