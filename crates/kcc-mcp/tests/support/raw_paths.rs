//! Raw tool authorization must describe exactly the command sent to the router.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the raw MCP security boundary"
)]
mod tests {
    use kcc_app::permissions::{Permission, Role};
    use kcc_testkit::{FakeRouter, model::Profile};
    use rmcp::model::CallToolRequestParams;
    use serde_json::{Value, json};
    use url::form_urlencoded::byte_serialize;

    use crate::lab::{Lab, TestResult, admin};

    /// Mismatched write paths cannot bypass destructive gating or falsify persistence.
    // NOT cancel-safe: the fixture owns router and MCP tasks until explicit shutdown.
    #[tokio::test]
    async fn mismatched_mutations_are_refused_before_router_access() -> TestResult {
        for (tool, path) in [
            ("kcc_rci_execute", ["system", "reboot"]),
            ("kcc_rci_execute", ["system", "description"]),
        ] {
            let lab = Lab::start_with_destructive(
                vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
                admin(),
                false,
            )
            .await?;
            let before = lab.requests("lab-1")?;
            let reply = lab
                .call(
                    tool,
                    json!({"host":"lab-1", "catalog_path":"system country",
                        "path":path, "value":{}}),
                    false,
                )
                .await?;
            assert_eq!(reply.error(), Some("validation_failed"), "{tool} {path:?}");
            assert_eq!(
                lab.requests("lab-1")?,
                before,
                "no discovery or command request"
            );
            assert_eq!(
                reply
                    .failure()
                    .and_then(|value| value.get("persists_immediately")),
                None
            );
            assert_refusal(&lab, tool)?;
            lab.stop().await?;
        }
        Ok(())
    }

    /// Delete refuses a different endpoint even when destructive calls are enabled.
    // NOT cancel-safe: the fixture owns router and MCP tasks until explicit shutdown.
    #[tokio::test]
    async fn mismatched_delete_is_refused_before_router_access() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let before = lab.requests("lab-1")?;
        let reply = lab
            .call(
                "kcc_rci_delete",
                json!({
                    "host":"lab-1", "catalog_path":"system country",
                    "path":["ip","host"], "confirm":true
                }),
                false,
            )
            .await?;
        assert_eq!(reply.error(), Some("validation_failed"));
        assert_eq!(lab.requests("lab-1")?, before);
        assert_eq!(
            reply
                .failure()
                .and_then(|value| value.get("persists_immediately")),
            None
        );
        assert_refusal(&lab, "kcc_rci_delete")?;
        lab.stop().await
    }

    /// Matching raw commands preserve object selectors outside the URL path.
    // NOT cancel-safe: the fixture owns router and MCP tasks until explicit shutdown.
    #[tokio::test]
    async fn matching_reads_keep_instance_names_in_query_slots() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        for name in ["Bridge0", "WifiMaster0/AccessPoint0"] {
            let encoded = byte_serialize(name.as_bytes()).collect::<String>();
            let reply = lab
                .call(
                    "kcc_rci_read",
                    json!({
                        "host":"lab-1", "catalog_path":"show interface",
                        "path":["show","interface"], "value":{"name":name}
                    }),
                    false,
                )
                .await?;
            assert!(
                reply.value()?.get("value").is_some(),
                "matching read succeeds"
            );
            assert!(
                lab.router("lab-1")?
                    .request_log()
                    .iter()
                    .any(|request| request.path() == "/rci/show/interface"
                        && request
                            .query()
                            .iter()
                            .any(|(key, value)| key == "name" && value == &encoded)),
                "the instance stays in the catalog query slot"
            );
        }
        lab.stop().await
    }

    /// A viewer cannot turn a show read into a write through GET-to-POST fallback.
    // NOT cancel-safe: the fixture owns router and MCP tasks until explicit shutdown.
    #[tokio::test]
    async fn mismatched_viewer_read_is_refused_before_router_access() -> TestResult {
        let viewer = Role::new(
            "viewer".to_owned(),
            [Permission::Read],
            vec!["*".to_owned()],
        );
        let lab = Lab::start_with_destructive(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            viewer,
            false,
        )
        .await?;
        let before = lab.requests("lab-1")?;
        let reply = lab
            .call(
                "kcc_rci_read",
                json!({"host":"lab-1", "catalog_path":"show version",
                "path":["system","reboot"]}),
                false,
            )
            .await?;
        assert_eq!(reply.error(), Some("validation_failed"));
        assert_eq!(
            lab.requests("lab-1")?,
            before,
            "no discovery, GET or fallback POST"
        );
        assert_eq!(
            reply
                .failure()
                .and_then(|value| value.get("persists_immediately")),
            None
        );
        assert_refusal(&lab, "kcc_rci_read")?;
        lab.stop().await
    }

    /// The removed selector kinds are not accepted, so nothing unvalidated can be sent.
    // NOT cancel-safe: the fixture owns router and MCP tasks until explicit shutdown.
    #[tokio::test]
    async fn removed_selector_kinds_are_refused_before_router_access() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let before = lab.requests("lab-1")?;
        for kind in ["show_rc", "show_sc"] {
            let request = json!({"host":"lab-1", "catalog_path":"show running-config",
                "path":["show","running-config"], "kind":kind, "value":{"system":{}}});
            let Value::Object(arguments) = request else {
                return Err("arguments must be an object".into());
            };
            // The enum is closed at argument parsing, so the reply is not the tool's JSON error.
            let result = lab
                .client
                .call_tool(CallToolRequestParams::new("kcc_rci_read").with_arguments(arguments))
                .await;
            assert!(
                result.is_err() || result.is_ok_and(|reply| reply.is_error == Some(true)),
                "{kind} must be refused"
            );
            assert_eq!(lab.requests("lab-1")?, before, "{kind} reached the router");
        }
        lab.stop().await
    }

    /// The surviving read validates `show version` and sends that same command. The fake router
    /// serves no `show running-config`, so `show version` is the positive control.
    // NOT cancel-safe: the fixture owns router and MCP tasks until explicit shutdown.
    #[tokio::test]
    async fn show_read_returns_the_router_reply() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let reply = lab
            .call(
                "kcc_rci_read",
                json!({"host":"lab-1", "catalog_path":"show version",
                "path":["show","version"], "kind":"get"}),
                false,
            )
            .await?;
        assert_eq!(reply.error(), None, "{reply:?}");
        assert_eq!(
            reply.value()?.pointer("/value/hw_id"),
            Some(&json!("KN-1811")),
            "{reply:?}"
        );
        lab.stop().await
    }

    /// An honest setting GET never becomes a mutation when the router returns 404.
    // NOT cancel-safe: the fixture owns router and MCP tasks until explicit shutdown.
    #[tokio::test]
    async fn setting_read_never_uses_show_post_fallback() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let reply = lab
            .call(
                "kcc_rci_read",
                json!({
                    "host":"lab-1", "catalog_path":"system country", "path":["system","country"]
                }),
                false,
            )
            .await?;
        assert_eq!(reply.error(), Some("router_rejected"));
        let methods = lab
            .router("lab-1")?
            .request_log()
            .iter()
            .filter(|request| request.path() == "/rci/system/country")
            .map(|request| request.method().to_string())
            .collect::<Vec<_>>();
        assert_eq!(methods, ["GET"]);
        lab.stop().await
    }

    /// One rejected call has one refusal receipt and no successful change receipt.
    fn assert_refusal(lab: &Lab, tool: &str) -> TestResult {
        let entries = lab.audit()?;
        let [entry] = entries.as_slice() else {
            return Err(format!("expected one refusal, got {} entries", entries.len()).into());
        };
        assert_eq!(entry.action, format!("mcp.{tool}"));
        assert_eq!(entry.router.as_deref(), Some("lab-1"));
        assert_eq!(entry.outcome, "refused");
        assert_eq!(entry.params_redacted, json!({"reason":"validation_failed"}));
        Ok(())
    }
}
