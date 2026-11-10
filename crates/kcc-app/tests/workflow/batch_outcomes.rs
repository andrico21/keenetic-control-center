//! Batch receipts distinguish router refusal from successful application.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions establish batch completion semantics"
)]
mod tests {
    use core::error::Error;

    use kcc_app::{
        audit::read_entries,
        permissions::Permission,
        workflow::{BatchChangeRequest, BatchItem},
    };
    use kcc_catalog::{Catalog, HttpMethod};
    use kcc_testkit::FaultInjection;
    use serde_json::json;

    use crate::Fixture;

    /// Only successful items contribute to persistence and the audit outcome.
    // NOT cancel-safe: the fixture owns router tasks and writes.
    #[tokio::test]
    async fn batch_refusals_report_failed_or_partial_receipts() -> Result<(), Box<dyn Error>> {
        for (rejected, mixed, outcome, successful, failed) in [
            ("/system/country", false, "failed", 0_usize, 1_usize),
            (
                "/system/description",
                true,
                "partially_applied_persisted",
                1,
                1,
            ),
            ("/system/country", true, "partially_applied_unsaved", 1, 1),
            ("/absent", true, "applied_unsaved", 2, 0),
        ] {
            let fixture =
                Fixture::spawn(FaultInjection::default().refuse_batch_pointer(rejected.to_owned()))
                    .await?;
            let info = fixture.registry.poll_info("router").await?;
            let catalog = Catalog::for_router(&info)?;
            let mut values = vec![json!({"system":{"country":{"country":"DE"}}})];
            if mixed {
                values.push(json!({"system":{"description":{"description":"lab"}}}));
            }
            let items = values
                .into_iter()
                .map(|value| {
                    let validated = catalog
                        .validate("", HttpMethod::Post, &value)
                        .map_err(|issues| format!("{issues:?}"))?;
                    Ok(BatchItem::new(value, validated))
                })
                .collect::<Result<Vec<_>, String>>()?;
            let mut changes = fixture.begin(None).await?;
            let result = changes
                .apply_batch(BatchChangeRequest::new(
                    items,
                    Vec::new(),
                    Permission::Write,
                    json!({"validated":true}),
                ))
                .await?;
            assert_eq!(
                result
                    .responses
                    .iter()
                    .filter(|response| response.is_ok())
                    .count(),
                successful
            );
            assert_eq!(
                result
                    .responses
                    .iter()
                    .filter(|response| response.is_err())
                    .count(),
                failed
            );
            assert_eq!(result.unsaved, outcome.ends_with("unsaved"));
            assert_eq!(result.persists_immediately, outcome.ends_with("persisted"));
            let expected_paths = if rejected == "/system/country" {
                Vec::<String>::new()
            } else {
                vec!["system country".to_owned()]
            };
            assert_eq!(result.persisted_paths, expected_paths);
            let entries = read_entries(&fixture.directory.path().join("state"))?;
            let entry = entries
                .iter()
                .find(|entry| entry.action == "router.change_batch")
                .ok_or("batch audit")?;
            assert_eq!(entry.outcome, outcome, "{rejected}");
            if failed != 0 {
                assert_eq!(
                    entry.params_redacted,
                    json!({"error":"router_rejected","succeeded":successful,"failed":failed})
                );
            }
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }
}
