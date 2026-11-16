//! MCP migration records keep router leases and same-plan router identities separate.
extern crate alloc;

#[path = "support/lab.rs"]
mod lab;
#[path = "migration_lease/records.rs"]
mod records;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "acceptance assertions establish the migration record lifecycle"
)]
#[expect(
    clippy::missing_panics_doc,
    reason = "acceptance assertions establish the migration record lifecycle"
)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the migration record lifecycle"
)]
mod tests {
    use kcc_testkit::{FakeRouter, migration, model::Profile};
    use serde_json::{Value, json};

    use super::lab::{Lab, TestResult, admin};

    /// A migration target using one of the two supported recovery mechanisms.
    fn target(mode: &str) -> TestResult<FakeRouter> {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        Ok(FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario))
    }

    /// Plans `source` onto `host`, resolving every blocking item conservatively.
    async fn plan(lab: &Lab, host: &str, source: &str) -> TestResult<String> {
        let first = lab
            .call(
                "kcc_migration_plan",
                json!({"host":host, "source":source}),
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
                    "host":host,
                    "source":source,
                    "overwrite":indices(true),
                    "exclude":indices(false)
                }),
                false,
            )
            .await?;
        Ok(planned
            .value()?
            .get("plan_id")
            .and_then(Value::as_str)
            .ok_or("missing plan id")?
            .to_owned())
    }

    /// Applies a reviewed migration and returns only after verification.
    async fn apply(lab: &mut Lab, host: &str, plan_id: &str) -> TestResult {
        let applied = lab
            .call(
                "kcc_migration_apply",
                json!({"host":host, "plan_id":plan_id, "confirm":true}),
                true,
            )
            .await?;
        assert_eq!(
            applied.value()?.pointer("/apply/verified"),
            Some(&json!(true))
        );
        assert_ne!(lab.progress_received().await, []);
        Ok(())
    }

    /// Finishes an applied migration, then proves a normal MCP write can acquire its lease.
    async fn finish_releases_lease(mode: &str, action: &str) -> TestResult {
        let migration_target = target(mode)?;
        let mut lab = Lab::start(
            vec![
                ("lab-src", FakeRouter::builder(Profile::default()).build()?),
                ("lab-1", migration_target),
            ],
            admin(),
        )
        .await?;
        let plan_id = plan(&lab, "lab-1", "lab-src").await?;
        assert!(lab.tool_names().await?.contains("kcc_migration_finish"));
        apply(&mut lab, "lab-1", &plan_id).await?;

        let finished = lab
            .call(
                "kcc_migration_finish",
                json!({"host":"lab-1", "plan_id":plan_id, "action":action, "confirm":true}),
                false,
            )
            .await?;
        assert_eq!(
            finished.value()?.pointer("/apply/finished"),
            Some(&json!(true))
        );
        let write = lab
            .call(
                "kcc_interfaces_write",
                json!({
                    "host":"lab-1",
                    "op":"description",
                    "name":"Bridge0",
                    "description":"lease-released"
                }),
                false,
            )
            .await?;
        assert_eq!(write.value()?.get("applied"), Some(&json!(true)));
        lab.stop().await
    }

    #[tokio::test]
    async fn router_commit_releases_lease() -> TestResult {
        finish_releases_lease("router", "commit").await
    }

    #[tokio::test]
    async fn router_rollback_releases_lease() -> TestResult {
        finish_releases_lease("router", "rollback").await
    }

    #[tokio::test]
    async fn extender_commit_releases_lease() -> TestResult {
        finish_releases_lease("extender", "commit").await
    }

    #[tokio::test]
    async fn extender_rollback_releases_lease() -> TestResult {
        finish_releases_lease("extender", "rollback").await
    }

    /// Re-planning cannot discard an applied migration whose recovery timer is still armed.
    #[tokio::test]
    async fn applied_migration_refuses_replacement() -> TestResult {
        let mut lab = Lab::start(
            vec![
                ("lab-src", FakeRouter::builder(Profile::default()).build()?),
                ("lab-1", target("router")?),
            ],
            admin(),
        )
        .await?;
        let plan_id = plan(&lab, "lab-1", "lab-src").await?;
        apply(&mut lab, "lab-1", &plan_id).await?;

        let before = lab.requests("lab-1")?;
        let replacement = lab
            .call(
                "kcc_migration_plan",
                json!({"host":"lab-1", "source":"lab-src"}),
                false,
            )
            .await?;

        assert_eq!(replacement.error(), Some("conflict"), "{replacement:?}");
        assert!(replacement.failure().is_some());
        assert!(
            lab.requests("lab-1")? > before,
            "planning reads the target before record admission"
        );
        assert!(lab.router("lab-1")?.recovery_armed());
        let finished = lab
            .call(
                "kcc_migration_finish",
                json!({"host":"lab-1", "plan_id":plan_id, "action":"rollback", "confirm":true}),
                false,
            )
            .await?;
        assert_eq!(
            finished.value()?.pointer("/apply/finished"),
            Some(&json!(true))
        );
        assert_ne!(lab.audit()?, []);
        lab.stop().await
    }

    /// Identical planner ids on distinct targets remain independently addressable.
    #[tokio::test]
    async fn identical_plan_ids_on_distinct_targets_do_not_collide() -> TestResult {
        let lab = Lab::start(
            vec![
                ("lab-src", FakeRouter::builder(Profile::default()).build()?),
                ("lab-1", target("router")?),
                ("lab-2", target("router")?),
            ],
            admin(),
        )
        .await?;
        let first_id = plan(&lab, "lab-1", "lab-src").await?;
        let second_id = plan(&lab, "lab-2", "lab-src").await?;
        assert_ne!(first_id, second_id, "router-qualified ids must differ");

        for (host, plan_id) in [("lab-1", first_id), ("lab-2", second_id)] {
            let report = lab
                .call(
                    "kcc_migration_report",
                    json!({"host":host, "plan_id":plan_id}),
                    false,
                )
                .await?;
            assert_eq!(report.value()?.get("target"), Some(&json!(host)));
        }
        lab.stop().await
    }

    /// Distinct source plans for one target coexist until one is applied.
    #[tokio::test]
    async fn same_target_keeps_distinct_source_plans() -> TestResult {
        let mut lab = Lab::start(
            vec![
                ("lab-src", FakeRouter::builder(Profile::default()).build()?),
                ("lab-alt", FakeRouter::builder(Profile::default()).build()?),
                ("lab-1", target("router")?),
            ],
            admin(),
        )
        .await?;
        let alternate = lab.registry.client("lab-alt").await?;
        drop(
            alternate
                .parse("interface Bridge0 description alternate-source")
                .await?,
        );
        drop(alternate.parse("system configuration save").await?);

        let first_id = plan(&lab, "lab-1", "lab-src").await?;
        let replacement_id = plan(&lab, "lab-1", "lab-src").await?;
        let second_id = plan(&lab, "lab-1", "lab-alt").await?;
        assert_eq!(replacement_id, first_id);
        assert_ne!(second_id, first_id);

        for plan_id in [&first_id, &second_id] {
            let report = lab
                .call(
                    "kcc_migration_report",
                    json!({"host":"lab-1", "plan_id":plan_id}),
                    false,
                )
                .await?;
            assert_eq!(report.value()?.get("plan_id"), Some(&json!(plan_id)));
        }
        apply(&mut lab, "lab-1", &second_id).await?;
        let finished = lab
            .call(
                "kcc_migration_finish",
                json!({
                    "host":"lab-1", "plan_id":second_id, "action":"rollback", "confirm":true
                }),
                false,
            )
            .await?;
        assert_eq!(
            finished.value()?.pointer("/apply/finished"),
            Some(&json!(true))
        );
        lab.stop().await
    }
}
