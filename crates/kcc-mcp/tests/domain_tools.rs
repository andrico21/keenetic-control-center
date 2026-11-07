//! Domain tool registry, generated reference, and domain reads/writes over a real session.
extern crate alloc;

#[path = "support/lab.rs"]
mod lab;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the MCP tool contract"
)]
mod tests {
    use alloc::collections::BTreeSet;
    use std::fs;

    use kcc_app::audit::ActorKind;
    use kcc_mcp::registry::{definitions::tools, docs::markdown};
    use kcc_testkit::{FakeRouter, model::Profile};
    use serde_json::json;

    use super::lab::{Lab, TestResult, admin, lab_only};

    /// `core` stays small, the full inventory stays under the client tool budget, and the
    /// session lists exactly the registry.
    #[tokio::test]
    async fn tool_counts_stay_within_limits_and_match_the_session() -> TestResult {
        let all = tools();
        let core = all.iter().filter(|tool| tool.toolset == "core").count();
        assert!(core <= 25, "core has {core} tools");
        assert!(all.len() <= 70, "{} tools registered", all.len());
        for merged in [
            "kcc_internet_read",
            "kcc_storage_read",
            "kcc_schedules_read",
        ] {
            assert!(
                all.iter().all(|tool| tool.name != merged),
                "{merged} must merge into kcc_system_read"
            );
        }
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let listed = lab.tool_names().await?;
        let registered = all
            .iter()
            .map(|tool| tool.name.to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(listed, registered);
        lab.stop().await
    }

    /// `docs/MCP_TOOLS.md` is the output of `cargo xtask gen-tool-docs`.
    #[test]
    fn committed_tool_reference_matches_the_registry() -> TestResult {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/MCP_TOOLS.md");
        let committed = fs::read_to_string(path)?;
        assert!(
            committed == markdown(),
            "docs/MCP_TOOLS.md is stale; run `cargo xtask gen-tool-docs`"
        );
        Ok(())
    }

    /// A domain write goes through the planner and change set, is audited, and stays unsaved.
    #[tokio::test]
    async fn system_write_applies_unsaved_and_is_audited() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let version = lab
            .call(
                "kcc_system_read",
                json!({"host": "lab-1", "op": "version"}),
                false,
            )
            .await?;
        assert!(
            version.value()?.pointer("/value/model").is_some(),
            "{version:?}"
        );
        let written = lab
            .call(
                "kcc_system_write",
                json!({"host": "lab-1", "op": "description", "value": "mcp-written"}),
                false,
            )
            .await?;
        assert_eq!(written.value()?.get("unsaved"), Some(&json!(true)));
        let state = lab
            .call("kcc_config_state", json!({"host": "lab-1"}), false)
            .await?;
        assert_eq!(
            state.value()?.pointer("/fail_safe/active"),
            Some(&json!(false))
        );
        assert!(
            state
                .value()?
                .get("unsaved")
                .is_some_and(serde_json::Value::is_boolean)
        );
        assert!(
            lab.audit()?
                .iter()
                .any(|entry| entry.actor.kind == ActorKind::Mcp
                    && entry.router.as_deref() == Some("lab-1")
                    && entry.target.as_deref() == Some("system description")),
            "the write is audited as the MCP identity"
        );
        lab.stop().await
    }

    /// A diagnostic job started with a progress token reports progress until it ends.
    #[tokio::test]
    async fn diagnostic_job_streams_progress() -> TestResult {
        let mut lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let started = lab
            .call(
                "kcc_diagnostics_write",
                json!({"host": "lab-1", "op": "ping", "arguments": {"host": "192.0.2.1"}}),
                true,
            )
            .await?;
        assert_eq!(
            started.value()?.get("status"),
            Some(&json!("completed")),
            "{started:?}"
        );
        assert!(
            !lab.progress_received().await.is_empty(),
            "no progress notification arrived"
        );
        lab.stop().await
    }

    /// A destructive operation without `confirm`, or outside the caller's scope, is refused
    /// before the router receives anything.
    #[tokio::test]
    async fn refused_domain_operations_send_nothing() -> TestResult {
        let routers = vec![
            ("lab-1", FakeRouter::builder(Profile::default()).build()?),
            ("prod-1", FakeRouter::builder(Profile::default()).build()?),
        ];
        let lab = Lab::start(routers, lab_only()).await?;
        let before = (lab.requests("lab-1")?, lab.requests("prod-1")?);
        let reboot = lab
            .call(
                "kcc_system_write",
                json!({"host": "lab-1", "op": "reboot"}),
                false,
            )
            .await?;
        assert_eq!(reboot.error(), Some("forbidden"));
        let outside = lab
            .call(
                "kcc_system_read",
                json!({"host": "prod-1", "op": "version"}),
                false,
            )
            .await?;
        assert_eq!(outside.error(), Some("forbidden"));
        let unknown = lab
            .call(
                "kcc_system_write",
                json!({"host": "lab-1", "op": "rm_rf"}),
                false,
            )
            .await?;
        assert_eq!(unknown.error(), Some("invalid_arguments"));
        assert_eq!((lab.requests("lab-1")?, lab.requests("prod-1")?), before);
        lab.stop().await
    }
}
