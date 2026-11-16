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
        workflow::{
            BatchChangeRequest, BatchItem, ChangeRequest, CliChangeRequest, CliCommand,
            WorkflowError,
        },
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
            let mut values = vec![json!({"system":{"country":{"country":"DE"}}})];
            if mixed {
                values.push(json!({"system":{"description":{"description":"lab"}}}));
            }
            let items = values.into_iter().map(BatchItem::new).collect();
            let mut changes = fixture.begin().await?;
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

    /// Read answers never count as applied or unsaved changes in mixed batches.
    // NOT cancel-safe: the fixture owns router tasks and writes.
    #[tokio::test]
    async fn mixed_read_batches_count_only_changes() -> Result<(), Box<dyn Error>> {
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
            let fixture =
                Fixture::spawn(FaultInjection::default().refuse_batch_pointer(rejected.to_owned()))
                    .await?;
            let mut values = vec![json!({"show":{"version":{}}})];
            if ordinary {
                values.push(json!({"system":{"description":{"description":"lab"}}}));
            }
            if !ordinary || rejected == "/system/country" {
                values.push(json!({"system":{"country":{"country":"DE"}}}));
            }
            let items = values.into_iter().map(BatchItem::new).collect();
            let mut changes = fixture.begin().await?;
            let result = changes
                .apply_batch(BatchChangeRequest::new(
                    items,
                    Vec::new(),
                    Permission::Write,
                    json!({"validated":true}),
                ))
                .await?;
            assert_eq!(result.unsaved, unsaved, "{outcome}");
            assert_eq!(result.applied_changes, usize::from(ordinary || persisted));
            assert_eq!(result.persists_immediately, persisted, "{outcome}");
            assert_eq!(
                result.persisted_paths,
                if persisted {
                    vec!["system country"]
                } else {
                    Vec::new()
                }
            );
            let entries = read_entries(&fixture.directory.path().join("state"))?;
            let entry = entries
                .iter()
                .find(|entry| entry.action == "router.change_batch")
                .ok_or("batch audit")?;
            assert_eq!(entry.outcome, outcome);
            if rejected == "/system/country" {
                assert_eq!(
                    entry.params_redacted,
                    json!({"error":"router_rejected","succeeded":if ordinary {2_usize} else {1_usize},"failed":1_usize})
                );
            }
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// A single RCI read reports its answer without unsaved changes.
    // NOT cancel-safe: the fixture owns router tasks until shutdown.
    #[tokio::test]
    async fn single_reads_leave_no_unsaved_changes() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(FaultInjection::default()).await?;
        let mut changes = fixture.begin().await?;
        let result = changes
            .apply(ChangeRequest::new(
                "show version".to_owned(),
                vec!["show".to_owned(), "version".to_owned()],
                json!({}),
                Vec::new(),
                Permission::Read,
                json!({}),
            ))
            .await?;
        assert!(!result.unsaved, "a single RCI read is not unsaved");
        let info = fixture.registry.poll_info("router").await?;
        let catalog = Catalog::for_router(&info)?;
        let validated = catalog
            .validate("show version", HttpMethod::Post, &json!({}))
            .map_err(|issues| format!("{issues:?}"))?;
        let parsed = changes
            .apply_cli(CliChangeRequest::new(
                vec![CliCommand::new("show version".to_owned(), validated)?],
                Vec::new(),
                Permission::Read,
                json!({}),
            ))
            .await;
        assert!(
            matches!(parsed, Err(WorkflowError::Rci(_))),
            "fake router rejects parser Show lines"
        );
        let outcomes = read_entries(&fixture.directory.path().join("state"))?
            .into_iter()
            .filter(|entry| matches!(entry.action.as_str(), "router.change" | "router.change_cli"))
            .map(|entry| entry.outcome)
            .collect::<Vec<_>>();
        assert_eq!(outcomes, ["success"]);
        drop(changes);
        fixture.shutdown().await?;
        Ok(())
    }

    /// An item is validated from the value it sends, never from the caller's own check of
    /// another body: a refused value stops the whole batch before anything is sent.
    // NOT cancel-safe: the fixture owns router tasks until shutdown.
    #[tokio::test]
    async fn batch_items_are_validated_from_their_values() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(FaultInjection::default()).await?;
        let info = fixture.registry.poll_info("router").await?;
        let catalog = Catalog::for_router(&info)?;
        let checked = json!({"description":"lab"});
        drop(
            catalog
                .validate("system description", HttpMethod::Post, &checked)
                .map_err(|issues| format!("{issues:?}"))?,
        );
        let sent = json!({"system":{"description":{"description":"lab","unknown-argument":true}}});
        let mut changes = fixture.begin().await?;
        let before = fixture.handle.request_log().len();
        let result = changes
            .apply_batch(BatchChangeRequest::new(
                vec![
                    BatchItem::new(json!({"system":{"description":checked}})),
                    BatchItem::new(sent),
                ],
                Vec::new(),
                Permission::Write,
                json!({"validated":true}),
            ))
            .await;
        assert!(
            matches!(&result, Err(WorkflowError::CatalogValidation { issues }) if !issues.is_empty()),
            "{result:?}"
        );
        assert_eq!(fixture.handle.request_log().len(), before);
        assert!(
            !fixture
                .handle
                .request_log()
                .iter()
                .any(|record| record.path() == "/rci/"),
            "no batch reached the router"
        );
        drop(changes);
        fixture.shutdown().await?;
        Ok(())
    }
}
