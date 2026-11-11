//! Domain tool registry, generated reference, and domain reads/writes over a real session.
extern crate alloc;

#[path = "support/lab.rs"]
mod lab;

#[path = "support/raw_paths.rs"]
mod raw_paths;

#[path = "support/raw_redaction.rs"]
mod raw_redaction;

#[path = "support/bracket.rs"]
mod bracket;
#[path = "support/curated_bracket.rs"]
mod curated_bracket;
#[path = "support/nested_risk.rs"]
mod nested_risk;
#[path = "support/runtime_bracket.rs"]
mod runtime_bracket;

#[path = "support/raw_parity.rs"]
mod raw_parity;

#[path = "support/batch_outcomes.rs"]
mod batch_outcomes;

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

    /// A typed service no-op returns a `verification_failed` tool error and one redacted audit
    /// receipt.
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
        let failed_entries = lab
            .audit()?
            .into_iter()
            .filter(|entry| entry.action == "mcp.kcc_services_write")
            .collect::<Vec<_>>();
        let [failed] = failed_entries.as_slice() else {
            return Err(
                format!("one failed MCP attempt must be audited: {failed_entries:?}").into(),
            );
        };
        assert_eq!(failed.actor.kind, ActorKind::Mcp);
        assert_eq!(failed.actor.id, "stdio");
        assert_eq!(failed.router.as_deref(), Some("lab-1"));
        assert_eq!(failed.outcome, "failed");
        assert_eq!(
            failed.params_redacted,
            json!({"error":"verification_failed"})
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

    /// Raw RCI audits distinguish router-persisted settings from ordinary unsaved changes.
    #[tokio::test]
    async fn raw_rci_audit_names_persisted_and_unsaved_outcomes() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let persisted = lab
            .call(
                "kcc_rci_execute",
                json!({
                    "host":"lab-1",
                    "catalog_path":"system country",
                    "path":["system","country"],
                    "value":{"country":"DE"}
                }),
                false,
            )
            .await?;
        assert_eq!(
            persisted.value()?.get("persists_immediately"),
            Some(&json!(true))
        );
        let ordinary = lab
            .call(
                "kcc_rci_execute",
                json!({
                    "host":"lab-1",
                    "catalog_path":"system description",
                    "path":["system","description"],
                    "value":{"description":"ordinary"}
                }),
                false,
            )
            .await?;
        assert_eq!(
            ordinary.value()?.get("persists_immediately"),
            Some(&json!(false))
        );
        let outcomes = lab
            .audit()?
            .into_iter()
            .filter(|entry| entry.action == "router.change")
            .map(|entry| entry.outcome)
            .collect::<Vec<_>>();
        assert_eq!(outcomes, ["applied_persisted", "applied_unsaved"]);
        lab.stop().await
    }

    /// A mixed raw RCI batch says which catalog path persisted and still requires a save.
    #[tokio::test]
    async fn raw_rci_batch_audit_keeps_mixed_changes_unsaved() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let mixed = lab
            .call(
                "kcc_rci_batch",
                json!({
                    "host":"lab-1",
                    "items":[
                        {"system":{"country":{"country":"DE"}}},
                        {"system":{"description":{"description":"mixed"}}}
                    ]
                }),
                false,
            )
            .await?;
        assert_eq!(
            mixed.value()?.get("persists_immediately"),
            Some(&json!(false))
        );
        assert_eq!(
            mixed.value()?.get("persisted_paths"),
            Some(&json!(["system country"]))
        );
        assert_eq!(mixed.value()?.get("save_required"), Some(&json!(true)));
        let persisted = lab
            .call(
                "kcc_rci_batch",
                json!({
                    "host":"lab-1",
                    "items":[
                        {"system":{"country":{"country":"US"}}},
                        {"system":{"country":{"country":"GB"}}}
                    ]
                }),
                false,
            )
            .await?;
        assert_eq!(
            persisted.value()?.get("persists_immediately"),
            Some(&json!(true))
        );
        assert_eq!(persisted.value()?.get("save_required"), None);
        let outcomes = lab
            .audit()?
            .into_iter()
            .filter(|entry| entry.action == "router.change_batch")
            .map(|entry| entry.outcome)
            .collect::<Vec<_>>();
        assert_eq!(outcomes, ["applied_unsaved", "applied_persisted"]);
        lab.stop().await
    }

    #[tokio::test]
    // NOT cancel-safe: fixture writes may apply before cancellation.
    async fn nested_mixed_rci_values_require_save_and_audit_unsaved() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let batch = lab
            .call(
                "kcc_rci_batch",
                json!({
                    "host":"lab-1",
                    "items":[{"system":{
                        "country":{"country":"DE"},
                        "description":{"description":"batch-mixed"}
                    }}]
                }),
                false,
            )
            .await?;
        let execute = lab
            .call(
                "kcc_rci_execute",
                json!({
                    "host":"lab-1",
                    "catalog_path":"system",
                    "path":["system"],
                    "value":{
                        "country":{"country":"US"},
                        "description":{"description":"execute-mixed"}
                    }
                }),
                false,
            )
            .await?;

        let deep_batch = lab
            .call(
                "kcc_rci_batch",
                json!({
                    "host":"lab-1", "items":[{"system":{"country":{"country":"DE"},
                    "ndss":{"dump-report":{"disable":{}}}}}]
                }),
                false,
            )
            .await?;
        let deep_value = lab
            .call(
                "kcc_rci_execute",
                json!({
                    "host":"lab-1", "catalog_path":"system", "path":["system"],
                    "value":{"country":{"country":"DE"},"ndss":{"dump-report":{"disable":{}}}}
                }),
                false,
            )
            .await?;
        for result in [
            batch.value()?,
            execute.value()?,
            deep_batch.value()?,
            deep_value.value()?,
        ] {
            assert_eq!(result.get("persists_immediately"), Some(&json!(false)));
            assert_eq!(result.get("unsaved"), Some(&json!(true)));
            assert_eq!(result.get("save_required"), Some(&json!(true)));
            assert_eq!(
                result.get("persisted_paths"),
                Some(&json!(["system country"]))
            );
        }
        let outcomes = lab
            .audit()?
            .into_iter()
            .filter(|entry| {
                matches!(
                    entry.action.as_str(),
                    "router.change_batch" | "router.change"
                )
            })
            .map(|entry| entry.outcome)
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes,
            [
                "applied_unsaved",
                "applied_unsaved",
                "applied_unsaved",
                "applied_unsaved"
            ]
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

    /// Firewall bindings succeed only when the running configuration reflects the write.
    #[tokio::test]
    async fn firewall_binding_success_and_ignored_write_use_domain_read_back() -> TestResult {
        let applied = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let input = json!({
            "host":"lab-1",
            "op":"binding",
            "acl":"McpAcl",
            "interface":"ISP"
        });

        let reply = applied
            .call("kcc_firewall_write", input.clone(), false)
            .await?;
        assert_eq!(reply.value()?.get("unsaved"), Some(&json!(true)));
        assert!(
            applied
                .audit()?
                .iter()
                .any(|entry| entry.outcome == "applied_unsaved")
        );
        applied.stop().await?;

        let ignored = Lab::start(
            vec![(
                "lab-1",
                FakeRouter::builder(Profile::default())
                    .faults(FaultInjection::default().silent_noop_path("parse"))
                    .build()?,
            )],
            admin(),
        )
        .await?;

        let ignored_reply = ignored.call("kcc_firewall_write", input, false).await?;
        assert_eq!(
            ignored_reply.error(),
            Some("verification_failed"),
            "{ignored_reply:?}"
        );
        assert!(
            !ignored
                .audit()?
                .iter()
                .any(|entry| entry.outcome == "applied_unsaved")
        );
        ignored.stop().await
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

    /// A destructive operation without `confirm`, or outside the caller's scope, is refused,
    /// audited once with its reason, and never reaches a router.
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
        let refusals = lab
            .audit()?
            .into_iter()
            .filter(|entry| entry.action.starts_with("mcp."))
            .collect::<Vec<_>>();
        let [confirmation, scope] = refusals.as_slice() else {
            return Err(format!("two handler refusals must be audited: {refusals:?}").into());
        };
        assert_eq!(confirmation.action, "mcp.kcc_system_write");
        assert_eq!(confirmation.router.as_deref(), Some("lab-1"));
        assert_eq!(confirmation.outcome, "refused");
        assert_eq!(
            confirmation.params_redacted,
            json!({"reason":"confirm_required"})
        );
        assert_eq!(scope.action, "mcp.kcc_system_read");
        assert_eq!(scope.router.as_deref(), Some("prod-1"));
        assert_eq!(scope.outcome, "forbidden");
        assert_eq!(scope.params_redacted, json!({"reason":"forbidden"}));
        lab.stop().await
    }

    /// Invalid router-shaped arguments never enter failure audit records.
    #[tokio::test]
    async fn invalid_router_arguments_are_omitted_from_failure_audits() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let oversized = "A".repeat(300);
        for host in [oversized.as_str(), "../etc"] {
            let reply = lab
                .call(
                    "kcc_migration_apply",
                    json!({"host": host, "plan_id": "missing"}),
                    false,
                )
                .await?;
            assert_eq!(reply.error(), Some("invalid_arguments"));
        }
        let refusals = lab
            .audit()?
            .into_iter()
            .filter(|entry| entry.action == "mcp.kcc_migration_apply")
            .collect::<Vec<_>>();
        assert!(refusals.is_empty(), "{refusals:?}");
        lab.stop().await
    }

    /// A disabled destructive gate records its distinct refusal reason without transmission.
    #[tokio::test]
    async fn destructive_disabled_is_audited_without_router_contact() -> TestResult {
        let lab = Lab::start_with_destructive(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
            false,
        )
        .await?;
        let before = lab.requests("lab-1")?;
        let reply = lab
            .call(
                "kcc_system_write",
                json!({"host": "lab-1", "op": "reboot", "confirm": true}),
                false,
            )
            .await?;
        assert_eq!(reply.error(), Some("destructive_disabled"));
        assert_eq!(lab.requests("lab-1")?, before);
        let refusal = lab
            .audit()?
            .into_iter()
            .find(|entry| entry.action == "mcp.kcc_system_write")
            .ok_or("destructive refusal was not audited")?;
        assert_eq!(refusal.outcome, "refused");
        assert_eq!(refusal.router.as_deref(), Some("lab-1"));
        assert_eq!(
            refusal.params_redacted,
            json!({"reason":"destructive_disabled"})
        );
        lab.stop().await
    }
}
