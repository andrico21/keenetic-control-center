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
    use kcc_testkit::{FakeRouter, FaultInjection, model::Profile};
    use serde_json::json;

    use super::lab::{Lab, TestResult, admin, lab_only};

    /// A typed service no-op returns a `verification_failed` tool error naming the field,
    /// without an applied audit receipt.
    #[tokio::test]
    async fn silent_service_noop_returns_tool_error() -> TestResult {
        let lab = Lab::start(
            vec![(
                "lab-1",
                FakeRouter::builder(Profile::default())
                    .faults(FaultInjection::default().silent_noop_path("parse"))
                    .build()?,
            )],
            admin(),
        )
        .await?;
        let reply = lab
            .call(
                "kcc_services_write",
                json!({"host":"lab-1","op":"set_service","name":"iperf3","enabled":true}),
                false,
            )
            .await?;
        assert_eq!(reply.error(), Some("verification_failed"), "{reply:?}");
        assert_eq!(
            reply.failure().and_then(|failure| failure.get("field")),
            Some(&json!("/service")),
            "{reply:?}"
        );
        assert!(
            lab.router("lab-1")?
                .request_log()
                .iter()
                .any(|request| request.command() == Some("service iperf3"))
        );
        assert!(
            !lab.audit()?
                .iter()
                .any(|entry| entry.outcome == "applied_unsaved")
        );
        lab.stop().await
    }

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

    /// Firewall writes round-trip one full rule identity through the domain path.
    #[tokio::test]
    async fn firewall_rule_add_and_remove_round_trip_through_domain_read_back() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let rule = json!({
            "host":"lab-1",
            "op":"rule",
            "acl":"McpAcl",
            "verdict":"deny",
            "protocol":"udp",
            "source":"0.0.0.0",
            "destination":"198.51.100.20",
            "port":5_353_u16
        });

        let added = lab.call("kcc_firewall_write", rule.clone(), false).await?;
        assert_eq!(added.value()?.get("unsaved"), Some(&json!(true)));
        let after_add = lab.router("lab-1")?.running_config_text();
        assert!(
            after_add.contains(
                "deny udp 0.0.0.0 255.255.255.255 198.51.100.20 255.255.255.255 port eq 5353"
            ),
            "{after_add}"
        );

        let mut remove = rule;
        drop(
            remove
                .as_object_mut()
                .ok_or("rule is not an object")?
                .insert("remove".to_owned(), json!(true)),
        );
        let removed = lab.call("kcc_firewall_write", remove, false).await?;
        assert_eq!(removed.value()?.get("unsaved"), Some(&json!(true)));
        let after_remove = lab.router("lab-1")?.running_config_text();
        assert!(!after_remove.contains("deny udp 0.0.0.0"));
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
        assert_eq!(reboot.error(), Some("confirm_required"));
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
