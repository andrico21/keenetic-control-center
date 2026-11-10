//! Mixed read/write receipts at the MCP boundary.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions establish batch completion semantics"
)]
mod tests {
    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_testkit::{FakeRouter, FaultInjection, model::Profile};
    use serde_json::json;

    use crate::lab::{Lab, TestResult, admin};

    /// MCP notices and persistence describe the applied writes alone.
    // NOT cancel-safe: the fixture owns router and MCP tasks until shutdown.
    #[tokio::test]
    async fn mixed_read_batches_count_only_changes() -> TestResult {
        for (rejected, ordinary, outcome, unsaved, persisted) in [
            ("/system/country", false, "failed", false, false),
            ("/absent", false, "applied_persisted", false, true),
            ("/absent", true, "applied_unsaved", true, false),
            (
                "/system/country",
                true,
                "partially_applied_unsaved",
                true,
                false,
            ),
        ] {
            let lab = Lab::start(
                vec![(
                    "lab-1",
                    FakeRouter::builder(Profile::default())
                        .faults(FaultInjection::default().refuse_batch_pointer(rejected.to_owned()))
                        .build()?,
                )],
                admin(),
            )
            .await?;
            let mut items = vec![json!({"show":{"version":{}}})];
            if ordinary {
                items.push(json!({"system":{"description":{"description":"lab"}}}));
            }
            if !ordinary || rejected == "/system/country" {
                items.push(json!({"system":{"country":{"country":"DE"}}}));
            }
            let reply = lab
                .call(
                    "kcc_rci_batch",
                    json!({"host":"lab-1","items":items}),
                    false,
                )
                .await?;
            let value = reply.value()?;
            assert_eq!(value.get("unsaved"), Some(&json!(unsaved)), "{outcome}");
            assert_eq!(value.get("persists_immediately"), Some(&json!(persisted)));
            assert_eq!(value.get("persisted_paths"), None);
            assert_eq!(value.get("save_required"), None);
            let notice =
                persisted.then(|| json!(tr(Locale::En, keys::MCP_PERSISTS_IMMEDIATELY, None)));
            assert_eq!(value.get("notice"), notice.as_ref());
            let entries = lab.audit()?;
            let entry = entries
                .iter()
                .find(|entry| entry.action == "router.change_batch")
                .ok_or("batch audit")?;
            assert_eq!(entry.outcome, outcome);
            lab.stop().await?;
        }
        Ok(())
    }

    /// Nested namespace reads retain the read route even when a read is refused.
    // NOT cancel-safe: the fixture owns router and MCP tasks until shutdown.
    #[tokio::test]
    async fn namespace_reads_bypass_change_workflow() -> TestResult {
        for rejected in ["/absent", "/show/clock/date"] {
            let lab = Lab::start(
                vec![(
                    "lab-1",
                    FakeRouter::builder(Profile::default())
                        .faults(FaultInjection::default().refuse_batch_pointer(rejected.to_owned()))
                        .build()?,
                )],
                admin(),
            )
            .await?;
            let reply = lab
                .call(
                    "kcc_rci_batch",
                    json!({"host":"lab-1","items":[{"show":{"clock":{"date":{}}}}]}),
                    false,
                )
                .await?;
            let value = reply.value()?;
            assert_eq!(value.get("unsaved"), Some(&json!(false)));
            assert_eq!(value.get("persists_immediately"), Some(&json!(false)));
            assert_eq!(
                value.pointer("/responses/0/ok"),
                Some(&json!(rejected == "/absent"))
            );
            assert!(
                lab.audit()?
                    .iter()
                    .all(|entry| entry.action != "router.change_batch"),
                "reads leave no change audit"
            );
            lab.stop().await?;
        }
        Ok(())
    }
}
