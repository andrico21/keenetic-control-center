//! MCP persistence describes only successful batch items.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions establish batch completion semantics"
)]
mod tests {
    use kcc_testkit::{FakeRouter, FaultInjection, model::Profile};
    use serde_json::json;

    use crate::lab::{Lab, TestResult, admin};

    /// An HTTP 200 carrying an item error never claims that rejected item persisted.
    // NOT cancel-safe: the fixture owns router and MCP tasks until shutdown.
    #[tokio::test]
    async fn batch_refusals_classify_only_successful_items() -> TestResult {
        for (rejected, mixed, persists, unsaved, outcome) in [
            ("/system/country", false, false, false, "failed"),
            (
                "/system/description",
                true,
                true,
                false,
                "partially_applied_persisted",
            ),
            (
                "/system/country",
                true,
                false,
                true,
                "partially_applied_unsaved",
            ),
            ("/absent", true, false, true, "applied_unsaved"),
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
            let mut items = vec![json!({"system":{"country":{"country":"DE"}}})];
            if mixed {
                items.push(json!({"system":{"description":{"description":"lab"}}}));
            }
            let reply = lab
                .call(
                    "kcc_rci_batch",
                    json!({"host":"lab-1","items":items}),
                    false,
                )
                .await?;
            let value = reply.value()?;
            assert_eq!(
                value.get("persists_immediately"),
                Some(&json!(persists)),
                "{rejected}"
            );
            assert_eq!(value.get("unsaved"), Some(&json!(unsaved)), "{rejected}");
            if rejected == "/system/description" {
                assert_eq!(
                    value.get("persisted_paths"),
                    Some(&json!(["system country"]))
                );
            }
            if rejected == "/system/country" {
                assert_eq!(value.get("notice"), None);
                assert_eq!(value.get("persisted_paths"), None);
                assert_eq!(value.pointer("/responses/0/ok"), Some(&json!(false)));
            }
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
}
