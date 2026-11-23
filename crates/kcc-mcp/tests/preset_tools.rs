//! Preset tools over a real session: capture, a write-free dry run, the confirmed apply and
//! its finish, the confirmation gate, and source/target scoping.
extern crate alloc;

#[path = "support/lab.rs"]
mod lab;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the preset tool contract"
)]
mod tests {
    use kcc_app::{
        audit::ActorKind,
        permissions::{Permission, Role},
    };
    use kcc_mcp::registry::definitions::tools;
    use kcc_testkit::{FakeRouter, RequestRecord, migration, model::Profile};
    use serde_json::{Value, json};

    use super::lab::{Lab, TestResult, admin, lab_only};

    /// The DNS line the source router holds.
    const UPSTREAM: &str = "dns-proxy tls upstream 1.1.1.1 853";

    /// A target in router mode, as the migration engine's recovery timer expects.
    fn target() -> TestResult<FakeRouter> {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        Ok(FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario))
    }

    /// Saves `UPSTREAM` on `host` through the raw CLI tool.
    async fn seed(lab: &Lab, host: &str) -> TestResult {
        let parsed = lab
            .call(
                "kcc_cli_parse",
                json!({"host": host, "line": UPSTREAM}),
                false,
            )
            .await?;
        assert!(parsed.value().is_ok(), "{parsed:?}");
        let saved = lab
            .call("kcc_config_save", json!({"host": host}), false)
            .await?;
        assert_eq!(saved.value()?.get("saved"), Some(&json!(true)));
        Ok(())
    }

    /// Requests that could change router state: anything but a GET, the login, a `show`
    /// query, and the inventory's read-only `components list` and `easyconfig status`
    /// probes; any `parse` counts as a write.
    fn writes(log: &[RequestRecord]) -> Vec<String> {
        log.iter()
            .filter(|record| {
                let path = record.path();
                let read_post = record.method().as_str() == "POST"
                    && (path.starts_with("/rci/show/")
                        || matches!(
                            path,
                            "/auth" | "/rci/components/list" | "/rci/easyconfig/status"
                        ));
                (record.method().as_str() != "GET" && !read_post) || path.contains("parse")
            })
            .map(|record| format!("{} {}", record.method(), record.path()))
            .collect()
    }

    /// A dry run of `dns-secure` onto `lab-1` returns a ready plan after reading the
    /// inventory, and `lab-1` records no write.
    async fn dry_run_reads_only(lab: &Lab) -> TestResult {
        let before = lab.router("lab-1")?.request_log().len();
        let running = lab.router("lab-1")?.running_config_text();
        let dry = lab
            .call(
                "kcc_preset_apply",
                json!({"host": "lab-1", "preset_id": "dns-secure", "dry_run": true}),
                false,
            )
            .await?;
        let plan = dry.value()?;
        assert_eq!(plan.get("status"), Some(&json!("ready")), "{plan}");
        assert!(
            plan.pointer("/plan/items/0/disposition").is_some(),
            "{plan}"
        );
        let log = lab.router("lab-1")?.request_log();
        let read = log.get(before..).ok_or("request log shrank")?;
        let paths = read.iter().map(RequestRecord::path).collect::<Vec<_>>();
        for expected in [
            "/rci/show/version",
            "/ci/running-config.txt",
            "/rci/show/interface",
        ] {
            assert!(paths.contains(&expected), "{expected} not read: {paths:?}");
        }
        assert!(
            paths.iter().any(|path| path.contains("components")),
            "{paths:?}"
        );
        assert_eq!(writes(read), Vec::<String>::new());
        assert_eq!(lab.router("lab-1")?.running_config_text(), running);
        Ok(())
    }

    /// The missing preset confirmation appends one refusal for the target router.
    fn assert_confirmation_refusal(lab: &Lab) -> TestResult {
        let refusals = lab
            .audit()?
            .into_iter()
            .filter(|entry| entry.action == "mcp.kcc_preset_apply")
            .collect::<Vec<_>>();
        let [refused] = refusals.as_slice() else {
            return Err(format!("one missing confirmation must be audited: {refusals:?}").into());
        };
        assert_eq!(refused.outcome, "refused");
        assert_eq!(refused.router.as_deref(), Some("lab-1"));
        assert_eq!(
            refused.params_redacted,
            json!({"reason":"confirm_required"})
        );
        Ok(())
    }

    /// The presets toolset has its four tools and the inventory stays within its limits.
    #[test]
    fn presets_toolset_keeps_the_tool_budget() {
        let all = tools();
        let presets = all
            .iter()
            .filter(|tool| tool.toolset == "presets")
            .map(|tool| tool.name)
            .collect::<Vec<_>>();
        assert_eq!(
            presets,
            [
                "kcc_preset_list",
                "kcc_preset_capture",
                "kcc_preset_delete",
                "kcc_preset_apply"
            ]
        );
        assert!(all.iter().filter(|tool| tool.toolset == "core").count() <= 25);
        assert!(all.len() <= 72, "{} tools registered", all.len());
    }

    /// Capture `dns-secure`, dry-run without a single target write, refuse an unconfirmed
    /// apply, then apply, commit with the migration finish tool, and find the MCP audit.
    #[tokio::test]
    async fn dry_run_writes_nothing_then_the_apply_is_audited() -> TestResult {
        let routers = vec![
            ("lab-src", FakeRouter::builder(Profile::default()).build()?),
            ("lab-1", target()?),
        ];
        let mut lab = Lab::start(routers, admin()).await?;
        assert!(lab.tool_names().await?.contains("kcc_preset_apply"));
        seed(&lab, "lab-src").await?;
        let captured = lab
            .call(
                "kcc_preset_capture",
                json!({"source": "lab-src", "groups": ["dns-secure"], "name": "DNS secure"}),
                false,
            )
            .await?;
        let preset = captured.value()?;
        assert_eq!(preset.get("id"), Some(&json!("dns-secure")), "{preset}");
        assert_eq!(
            preset.pointer("/lines/0"),
            Some(&json!(UPSTREAM)),
            "{preset}"
        );
        let listed = lab.call("kcc_preset_list", json!({}), false).await?;
        assert_eq!(
            listed.value()?.pointer("/presets/0/id"),
            Some(&json!("dns-secure"))
        );

        dry_run_reads_only(&lab).await?;

        let quiet = lab.requests("lab-1")?;
        let unconfirmed = lab
            .call(
                "kcc_preset_apply",
                json!({"host": "lab-1", "preset_id": "dns-secure"}),
                false,
            )
            .await?;
        assert_eq!(unconfirmed.error(), Some("confirm_required"));
        assert_eq!(lab.requests("lab-1")?, quiet);
        assert_confirmation_refusal(&lab)?;

        let applied = lab
            .call(
                "kcc_preset_apply",
                json!({"host": "lab-1", "preset_id": "dns-secure", "confirm": true}),
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
        assert!(
            lab.router("lab-1")?
                .running_config_text()
                .contains(UPSTREAM)
        );
        let plan_id = outcome.get("plan_id").cloned().ok_or("no plan id")?;
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
                .contains(UPSTREAM)
        );
        let audited = lab.audit()?.into_iter().any(|entry| {
            entry.actor.kind == ActorKind::Mcp
                && entry.actor.id == "stdio"
                && entry.router.as_deref() == Some("lab-1")
        });
        assert!(audited, "the apply is not audited as the MCP identity");
        lab.stop().await
    }

    #[tokio::test]
    async fn apply_requires_complete_permissions_before_any_router_request() -> TestResult {
        let routers = vec![
            ("lab-src", FakeRouter::builder(Profile::default()).build()?),
            ("lab-1", target()?),
        ];
        let role = Role::new(
            "migrator".to_owned(),
            [
                Permission::Read,
                Permission::Write,
                Permission::Migrate,
                Permission::Destructive,
            ],
            vec!["*".to_owned()],
        );
        let lab = Lab::start(routers, role).await?;
        let captured = lab
            .call(
                "kcc_preset_capture",
                json!({"source":"lab-src", "groups":["dns-secure"], "name":"Recovery gate"}),
                false,
            )
            .await?;
        assert_eq!(captured.value()?.get("id"), Some(&json!("recovery-gate")));
        let before = (lab.requests("lab-src")?, lab.requests("lab-1")?);

        let refused = lab
            .call(
                "kcc_preset_apply",
                json!({"host":"lab-1", "preset_id":"recovery-gate", "confirm":true}),
                false,
            )
            .await?;

        assert_eq!(refused.error(), Some("forbidden"), "{refused:?}");
        assert_eq!((lab.requests("lab-src")?, lab.requests("lab-1")?), before);
        let entries = lab.audit()?;
        let failed = entries
            .iter()
            .find(|entry| entry.action == "mcp.kcc_preset_apply")
            .ok_or("missing preset apply refusal audit")?;
        assert_eq!(failed.outcome, "forbidden");
        lab.stop().await
    }

    /// A `lab-*` identity can neither capture from nor apply onto `prod-1`; the refused
    /// router receives no request at all.
    #[tokio::test]
    async fn scoped_identity_is_refused_before_any_request() -> TestResult {
        let routers = vec![
            ("prod-1", target()?),
            ("lab-src", FakeRouter::builder(Profile::default()).build()?),
        ];
        let lab = Lab::start(routers, lab_only()).await?;
        let before = (lab.requests("prod-1")?, lab.requests("lab-src")?);
        let capture = lab
            .call(
                "kcc_preset_capture",
                json!({"source": "prod-1", "groups": ["dns-secure"], "name": "prod"}),
                false,
            )
            .await?;
        assert_eq!(capture.error(), Some("forbidden"));
        assert_eq!((lab.requests("prod-1")?, lab.requests("lab-src")?), before);

        let transient = lab
            .call(
                "kcc_preset_capture",
                json!({"source": "lab-src", "groups": ["dns-secure"], "name": "copy", "transient": true}),
                false,
            )
            .await?;
        let id = transient.value()?.get("id").cloned().ok_or("no id")?;
        let quiet = lab.requests("prod-1")?;
        let apply = lab
            .call(
                "kcc_preset_apply",
                json!({"host": "prod-1", "preset_id": id, "dry_run": true}),
                false,
            )
            .await?;
        assert_eq!(apply.error(), Some("forbidden"));
        assert_eq!(lab.requests("prod-1")?, quiet);
        lab.stop().await
    }

    #[tokio::test]
    async fn scoped_identity_is_forbidden_before_preset_confirmation() -> TestResult {
        let lab = Lab::start(vec![("prod-1", target()?)], lab_only()).await?;
        let reply = lab
            .call(
                "kcc_preset_apply",
                json!({"host":"prod-1", "preset_id":"missing"}),
                false,
            )
            .await?;
        assert_eq!(reply.error(), Some("forbidden"));
        let entries = lab
            .audit()?
            .into_iter()
            .filter(|entry| entry.action == "mcp.kcc_preset_apply")
            .collect::<Vec<_>>();
        let [entry] = entries.as_slice() else {
            return Err(format!("one preset refusal must be audited: {entries:?}").into());
        };
        assert_eq!(entry.outcome, "forbidden");
        lab.stop().await
    }
}
