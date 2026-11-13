//! The built-in operator applies a preset over MCP: the recovery timer around the run is
//! authorized by `Migrate`, while a rollback finish still needs `Destructive`.
extern crate alloc;

#[path = "support/lab.rs"]
mod lab;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the operator apply contract"
)]
mod tests {
    use kcc_app::permissions::{Permission, Role, built_in_roles};
    use kcc_testkit::{FakeRouter, migration, model::Profile};
    use serde_json::{Value, json};

    use super::lab::{Lab, TestResult};

    /// The DNS line the source router holds.
    const UPSTREAM: &str = "dns-proxy tls upstream 1.1.1.1 853";

    /// The built-in role `name`.
    fn built_in(name: &str) -> TestResult<Role> {
        built_in_roles()
            .into_iter()
            .find(|role| role.name == name)
            .ok_or_else(|| format!("no built-in role {name}").into())
    }

    /// A session whose identity first holds every permission under `name`, seeds
    /// `lab-src`, captures preset `office`, then gets the built-in role `name`.
    async fn session(name: &str) -> TestResult<Lab> {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        let routers = vec![
            ("lab-src", FakeRouter::builder(Profile::default()).build()?),
            (
                "lab-1",
                FakeRouter::builder(Profile::default())
                    .build()?
                    .with_migration(scenario),
            ),
        ];
        let lab = Lab::start(
            routers,
            Role::new(name.to_owned(), Permission::ALL, vec!["*".to_owned()]),
        )
        .await?;
        let parsed = lab
            .call(
                "kcc_cli_parse",
                json!({"host": "lab-src", "line": UPSTREAM}),
                false,
            )
            .await?;
        assert!(parsed.value().is_ok(), "{parsed:?}");
        let saved = lab
            .call("kcc_config_save", json!({"host": "lab-src"}), false)
            .await?;
        assert_eq!(saved.value()?.get("saved"), Some(&json!(true)));
        let captured = lab
            .call(
                "kcc_preset_capture",
                json!({"source": "lab-src", "groups": ["dns-secure"], "name": "Office"}),
                false,
            )
            .await?;
        assert_eq!(captured.value()?.get("id"), Some(&json!("office")));
        lab.roles.replace(vec![built_in(name)?]);
        Ok(lab)
    }

    /// Parser commands `lab-1` received after the first `before` requests.
    fn commands(lab: &Lab, before: usize) -> TestResult<Vec<String>> {
        Ok(lab
            .router("lab-1")?
            .request_log()
            .iter()
            .skip(before)
            .filter_map(|record| record.command().map(str::to_owned))
            .collect())
    }

    /// Applies `office` onto `lab-1`, checks it reported progress, and returns its plan id.
    async fn applied(lab: &mut Lab) -> TestResult<Value> {
        let applied = lab
            .call(
                "kcc_preset_apply",
                json!({"host": "lab-1", "preset_id": "office", "confirm": true}),
                true,
            )
            .await?;
        assert!(
            !lab.progress_received().await.is_empty(),
            "apply reports progress"
        );
        let outcome = applied.value()?;
        assert_eq!(
            outcome.pointer("/apply/verified"),
            Some(&json!(true)),
            "{outcome}"
        );
        outcome
            .get("plan_id")
            .cloned()
            .ok_or_else(|| "no plan id".into())
    }

    /// The operator applies and commits: arm, the preset's line, then the commit.
    #[tokio::test]
    async fn operator_applies_a_preset_and_commits_it() -> TestResult {
        let mut lab = session("operator").await?;
        let tools = lab.tool_names().await?;
        assert!(
            tools.contains("kcc_preset_apply") && tools.contains("kcc_migration_finish"),
            "{tools:?}"
        );
        let before = lab.router("lab-1")?.request_log().len();

        let plan_id = applied(&mut lab).await?;
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
        let sent = commands(&lab, before)?;
        let order = [
            "system configuration fail-safe timer reboot 900",
            UPSTREAM,
            "system configuration fail-safe commit",
        ]
        .map(|line| sent.iter().position(|command| command == line));
        assert!(
            matches!(order, [Some(arm), Some(line), Some(commit)] if arm < line && line < commit),
            "{sent:?}"
        );
        assert!(
            lab.router("lab-1")?
                .startup_config_text()
                .contains(UPSTREAM)
        );
        assert!(!lab.router("lab-1")?.recovery_armed());
        lab.stop().await
    }

    /// The operator's rollback finish is refused before `lab-1` receives a request, and the
    /// run stays open for a commit.
    #[tokio::test]
    async fn operator_rollback_finish_is_refused_before_any_router_request() -> TestResult {
        let mut lab = session("operator").await?;
        let plan_id = applied(&mut lab).await?;
        let before = lab.requests("lab-1")?;

        let refused = lab
            .call(
                "kcc_migration_finish",
                json!({"host": "lab-1", "plan_id": plan_id, "action": "rollback", "confirm": true}),
                false,
            )
            .await?;

        assert_eq!(refused.error(), Some("forbidden"), "{refused:?}");
        assert_eq!(lab.requests("lab-1")?, before, "router traffic");
        assert!(lab.router("lab-1")?.recovery_armed(), "the run stays armed");
        let refusal = lab
            .audit()?
            .into_iter()
            .find(|entry| entry.action == "mcp.kcc_migration_finish")
            .ok_or("missing finish refusal audit")?;
        assert_eq!(refusal.outcome, "forbidden");
        lab.stop().await
    }

    /// A viewer's apply is refused before either router receives a request.
    #[tokio::test]
    async fn viewer_apply_is_refused_before_any_router_request() -> TestResult {
        let lab = session("viewer").await?;
        let before = (lab.requests("lab-src")?, lab.requests("lab-1")?);

        let refused = lab
            .call(
                "kcc_preset_apply",
                json!({"host": "lab-1", "preset_id": "office", "confirm": true}),
                false,
            )
            .await?;

        assert_eq!(refused.error(), Some("forbidden"), "{refused:?}");
        assert_eq!((lab.requests("lab-src")?, lab.requests("lab-1")?), before);
        lab.stop().await
    }
}
