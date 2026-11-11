//! Namespace batches must enter the protected workflow at the MCP boundary.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions establish namespace completion semantics"
)]
mod tests {
    use kcc_app::permissions::{Permission, Role};
    use kcc_testkit::{FakeRouter, model::Profile};
    use serde_json::{Value, json};

    use crate::lab::{Lab, TestResult, admin};

    /// Three batch shapes distinguish the item fallback from subtree classification.
    fn batches() -> [Value; 3] {
        [
            json!([{"ip":{"http":{}}}]),
            json!([{"show":{"version":{}}},{"ip":{"http":{}}}]),
            json!([{"show":{"version":{}},"ip":{"http":{}}}]),
        ]
    }

    /// Ordinary Write needs no MCP confirmation, but always creates an unsaved change receipt.
    // NOT cancel-safe: the fixture owns router and MCP tasks until shutdown.
    #[tokio::test]
    async fn namespace_batches_report_applied_unsaved() -> TestResult {
        for items in batches() {
            let lab = Lab::start_with_destructive(
                vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
                admin(),
                false,
            )
            .await?;
            let before = lab.router("lab-1")?.request_log().len();
            let reply = lab
                .call(
                    "kcc_rci_batch",
                    json!({"host":"lab-1","items":items,"confirm":false}),
                    false,
                )
                .await?;
            let value = reply.value()?;
            assert_eq!(value.get("unsaved"), Some(&json!(true)), "{items}");
            assert_eq!(value.get("persists_immediately"), Some(&json!(false)));
            assert_eq!(
                value.get("notice"),
                None,
                "ordinary changes carry no persistence notice"
            );
            assert_eq!(value.get("save_required"), None);
            let responses = value
                .get("responses")
                .and_then(Value::as_array)
                .ok_or("responses")?;
            assert_eq!(responses.len(), items.as_array().ok_or("items")?.len());
            assert!(
                responses
                    .iter()
                    .all(|response| response.get("ok") == Some(&json!(true))),
                "accepted items"
            );
            let entries = lab.audit()?;
            assert_eq!(
                entries
                    .iter()
                    .filter(|entry| entry.action == "router.change_batch")
                    .map(|entry| entry.outcome.as_str())
                    .collect::<Vec<_>>(),
                ["applied_unsaved"]
            );
            let log = lab.router("lab-1")?.request_log();
            assert_eq!(
                log.iter()
                    .skip(before)
                    .filter(|record| record.method() == "POST" && record.path() == "/rci/")
                    .count(),
                1
            );
            lab.stop().await?;
        }
        Ok(())
    }

    /// Raw RCI capability still enters the change workflow for an empty namespace.
    // NOT cancel-safe: the fixture owns router and MCP tasks until shutdown.
    #[tokio::test]
    async fn namespace_batches_with_raw_capability_enter_change_workflow() -> TestResult {
        for items in batches() {
            let role = Role::new(
                "reader".to_owned(),
                [Permission::Read, Permission::RawRci],
                vec!["*".to_owned()],
            );
            let lab = Lab::start(
                vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
                role,
            )
            .await?;
            let before = lab.router("lab-1")?.request_log().len();
            let reply = lab
                .call(
                    "kcc_rci_batch",
                    json!({"host":"lab-1","items":items}),
                    false,
                )
                .await?;
            let value = reply.value()?;
            assert_eq!(value.get("unsaved"), Some(&json!(true)), "{items}");
            let log = lab.router("lab-1")?.request_log();
            assert_eq!(
                log.iter()
                    .skip(before)
                    .filter(|record| record.method() == "POST" && record.path() == "/rci/")
                    .count(),
                1
            );
            assert_eq!(
                lab.audit()?
                    .iter()
                    .filter(|entry| entry.action == "router.change_batch")
                    .map(|entry| entry.outcome.as_str())
                    .collect::<Vec<_>>(),
                ["applied_unsaved"]
            );
            lab.stop().await?;
        }
        Ok(())
    }
}
