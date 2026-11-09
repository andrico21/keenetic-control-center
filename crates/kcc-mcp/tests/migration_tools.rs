//! Migration tools over a real session: scoping, the firmware-tier acknowledgement, and a
//! full plan, apply, and commit with progress notifications.
extern crate alloc;

#[path = "support/lab.rs"]
mod lab;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the migration tool contract"
)]
mod tests {
    use kcc_app::audit::ActorKind;
    use kcc_testkit::{
        FakeRouter, migration,
        model::{Firmware, Model, Profile},
    };
    use serde_json::{Value, json};

    use super::lab::{Lab, TestResult, admin, lab_only};

    /// A target in router mode, as the migration engine's recovery timer expects.
    fn target(profile: Profile) -> TestResult<FakeRouter> {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        Ok(FakeRouter::builder(profile)
            .build()?
            .with_migration(scenario))
    }

    /// Plans `source` onto `host`; a blocked plan is planned again with every conflict
    /// taking the source's value and every other blocking setting left out.
    async fn plan(lab: &Lab, host: &str, source: &str) -> TestResult<String> {
        let arguments = json!({"host": host, "source": source, "ack_documentation_tier": true});
        let first = lab.call("kcc_migration_plan", arguments, false).await?;
        let mut value = first.value()?.clone();
        if value.get("status") == Some(&json!("blocked")) {
            let blocked = value
                .get("blocked")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let indices = |conflict: bool| {
                blocked
                    .iter()
                    .filter(|item| {
                        (item.get("disposition") == Some(&json!("conflict"))) == conflict
                    })
                    .filter_map(|item| item.get("source_index").cloned())
                    .collect::<Vec<_>>()
            };
            let resolved = json!({
                "host": host,
                "source": source,
                "ack_documentation_tier": true,
                "overwrite": indices(true),
                "exclude": indices(false)
            });
            value = lab
                .call("kcc_migration_plan", resolved, false)
                .await?
                .value()?
                .clone();
        }
        assert_eq!(value.get("status"), Some(&json!("planned")), "{value}");
        Ok(value
            .get("plan_id")
            .and_then(Value::as_str)
            .ok_or("plan without id")?
            .to_owned())
    }

    /// Both migration confirmation gates append one refusal for the target router.
    fn assert_confirmation_refusals(lab: &Lab, plan_id: &str) -> TestResult {
        let refusals = lab
            .audit()?
            .into_iter()
            .filter(|entry| {
                matches!(
                    entry.action.as_str(),
                    "mcp.kcc_migration_apply" | "mcp.kcc_migration_finish"
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(refusals.len(), 2, "{plan_id}: {refusals:?}");
        assert!(refusals.iter().all(|entry| {
            entry.outcome == "refused"
                && entry.router.as_deref() == Some("lab-1")
                && entry.params_redacted == json!({"reason":"confirm_required"})
        }));
        Ok(())
    }

    /// An identity scoped to `lab-*` cannot plan from `prod-1`; neither router is contacted.
    #[tokio::test]
    async fn scoped_identity_cannot_plan_from_outside_its_scope() -> TestResult {
        let routers = vec![
            ("prod-1", FakeRouter::builder(Profile::default()).build()?),
            ("lab-1", target(Profile::default())?),
        ];
        let lab = Lab::start(routers, lab_only()).await?;
        assert!(lab.tool_names().await?.contains("kcc_migration_plan"));
        let before = (lab.requests("prod-1")?, lab.requests("lab-1")?);
        let reply = lab
            .call(
                "kcc_migration_plan",
                json!({"host": "lab-1", "source": "prod-1"}),
                false,
            )
            .await?;
        assert_eq!(reply.error(), Some("forbidden"));
        assert_eq!((lab.requests("prod-1")?, lab.requests("lab-1")?), before);
        let refusals = lab
            .audit()?
            .into_iter()
            .filter(|entry| entry.action == "mcp.kcc_migration_plan")
            .collect::<Vec<_>>();
        let [refused] = refusals.as_slice() else {
            return Err(format!("one scope refusal must be audited: {refusals:?}").into());
        };
        assert_eq!(refused.router.as_deref(), Some("lab-1"));
        lab.stop().await
    }

    #[tokio::test]
    async fn scoped_identity_is_forbidden_before_migration_confirmation() -> TestResult {
        let lab = Lab::start(vec![("prod-1", target(Profile::default())?)], lab_only()).await?;
        for (tool, arguments) in [
            (
                "kcc_migration_apply",
                json!({"host":"prod-1", "plan_id":"missing"}),
            ),
            (
                "kcc_migration_finish",
                json!({"host":"prod-1", "plan_id":"missing", "action":"commit"}),
            ),
        ] {
            let reply = lab.call(tool, arguments, false).await?;
            assert_eq!(reply.error(), Some("forbidden"), "{tool}");
        }
        let entries = lab
            .audit()?
            .into_iter()
            .filter(|entry| {
                matches!(
                    entry.action.as_str(),
                    "mcp.kcc_migration_apply" | "mcp.kcc_migration_finish"
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert!(entries.iter().all(|entry| entry.outcome == "forbidden"));
        lab.stop().await
    }

    /// Plan, apply with progress, and commit between two fake routers; apply without
    /// `confirm` is refused first.
    #[tokio::test]
    async fn plan_apply_commit_reports_progress() -> TestResult {
        let routers = vec![
            (
                "lab-src",
                FakeRouter::builder(Profile::latest(Model::Kn1010)).build()?,
            ),
            ("lab-1", target(Profile::default())?),
        ];
        let mut lab = Lab::start(routers, admin()).await?;
        let seeded = lab
            .call(
                "kcc_interfaces_write",
                json!({"host": "lab-src", "op": "description", "name": "Bridge0", "description": "office-network"}),
                false,
            )
            .await?;
        assert_eq!(seeded.value()?.get("applied"), Some(&json!(true)));
        let saved = lab
            .call("kcc_config_save", json!({"host": "lab-src"}), false)
            .await?;
        assert_eq!(saved.value()?.get("saved"), Some(&json!(true)));
        let plan_id = plan(&lab, "lab-1", "lab-src").await?;
        let unconfirmed = lab
            .call(
                "kcc_migration_apply",
                json!({"host": "lab-1", "plan_id": plan_id}),
                false,
            )
            .await?;
        assert_eq!(unconfirmed.error(), Some("confirm_required"));
        assert!(
            !lab.router("lab-1")?
                .startup_config_text()
                .contains("office-network")
        );
        let applied = lab
            .call(
                "kcc_migration_apply",
                json!({"host": "lab-1", "plan_id": plan_id, "confirm": true}),
                true,
            )
            .await?;
        let outcome = applied.value()?;
        assert!(
            outcome.get("job_id").and_then(Value::as_str).is_some(),
            "{outcome}"
        );
        assert_eq!(
            outcome.pointer("/apply/verified"),
            Some(&json!(true)),
            "{outcome}"
        );
        assert!(
            !lab.progress_received().await.is_empty(),
            "no progress notification arrived"
        );
        let finish_unconfirmed = lab
            .call(
                "kcc_migration_finish",
                json!({"host": "lab-1", "plan_id": plan_id, "action": "commit"}),
                false,
            )
            .await?;
        assert_eq!(finish_unconfirmed.error(), Some("confirm_required"));
        let finished = lab
            .call(
                "kcc_migration_finish",
                json!({"host": "lab-1", "plan_id": plan_id, "action": "commit", "confirm": true}),
                false,
            )
            .await?;
        assert_eq!(
            finished.value()?.pointer("/apply/finished"),
            Some(&json!(true))
        );
        assert!(
            lab.router("lab-1")?
                .startup_config_text()
                .contains("office-network"),
            "commit did not save the migrated description"
        );
        let report = lab
            .call(
                "kcc_migration_report",
                json!({"host": "lab-1", "plan_id": plan_id}),
                false,
            )
            .await?;
        assert_eq!(report.value()?.get("plan_id"), Some(&json!(plan_id)));
        assert_confirmation_refusals(&lab, &plan_id)?;
        lab.stop().await
    }

    /// A documentation-based (4.3.9) target refuses apply without the acknowledgement and
    /// proceeds with it, auditing the acknowledgement as the MCP identity.
    #[tokio::test]
    async fn documentation_tier_needs_an_audited_acknowledgement() -> TestResult {
        let legacy = || Profile::new(Model::Kn1811, Firmware::V4_3);
        let routers = vec![
            ("lab-old", FakeRouter::builder(legacy()?).build()?),
            ("lab-legacy", target(legacy()?)?),
        ];
        let lab = Lab::start(routers, admin()).await?;
        let plan_id = plan(&lab, "lab-legacy", "lab-old").await?;
        let refused = lab
            .call(
                "kcc_migration_apply",
                json!({"host": "lab-legacy", "plan_id": plan_id, "confirm": true}),
                false,
            )
            .await?;
        assert_eq!(refused.error(), Some("unverified_firmware_tier"));
        let acknowledged = json!({
            "host": "lab-legacy",
            "plan_id": plan_id,
            "confirm": true,
            "ack_documentation_tier": true
        });
        let applied = lab.call("kcc_migration_apply", acknowledged, false).await?;
        assert!(applied.value()?.get("job_id").is_some(), "{applied:?}");
        let audited = lab
            .audit()?
            .into_iter()
            .find(|entry| entry.action == "migration.ack_documentation_tier")
            .ok_or("acknowledgement not audited")?;
        assert_eq!(audited.actor.kind, ActorKind::Mcp);
        assert_eq!(audited.actor.id, "stdio");
        lab.stop().await
    }
}
