//! Accepted namespace requests carry ordinary-change receipts.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions establish namespace completion semantics"
)]
mod tests {
    use core::error::Error;

    use kcc_app::{
        audit::read_entries,
        permissions::Permission,
        workflow::{BatchChangeRequest, BatchItem},
    };
    use kcc_testkit::FaultInjection;
    use serde_json::json;

    use crate::Fixture;

    /// Namespace leaves count as applied changes in standalone, separate and shared items.
    // NOT cancel-safe: the fixture owns router tasks and writes until shutdown.
    #[tokio::test]
    async fn namespace_batches_report_applied_unsaved() -> Result<(), Box<dyn Error>> {
        for values in [
            vec![json!({"ip":{"http":{}}})],
            vec![json!({"show":{"version":{}}}), json!({"ip":{"http":{}}})],
            vec![json!({"show":{"version":{}},"ip":{"http":{}}})],
        ] {
            let fixture = Fixture::spawn(FaultInjection::default()).await?;
            let count = values.len();
            let items = values.into_iter().map(BatchItem::new).collect();
            let mut changes = fixture.begin().await?;
            let result = changes
                .apply_batch(BatchChangeRequest::new(
                    items,
                    Vec::new(),
                    Permission::RawRci,
                    json!({"validated":true}),
                ))
                .await?;
            assert_eq!(result.responses.len(), count);
            assert!(
                result.responses.iter().all(Result::is_ok),
                "fake accepted every item"
            );
            assert_eq!(result.applied_changes, 1);
            assert!(result.unsaved, "accepted namespace is an ordinary change");
            assert!(
                !result.persists_immediately,
                "namespace never proves persistence"
            );
            assert!(result.persisted_paths.is_empty(), "no persisted commands");
            assert_eq!(fixture.backups.list("router")?.len(), 1);
            let entries = read_entries(&fixture.directory.path().join("state"))?;
            let outcomes = entries
                .iter()
                .filter(|entry| entry.action == "router.change_batch")
                .map(|entry| entry.outcome.as_str())
                .collect::<Vec<_>>();
            assert_eq!(outcomes, ["applied_unsaved"]);
            let log = fixture.handle.request_log();
            assert_eq!(
                log.iter()
                    .filter(|record| record.method() == "POST" && record.path() == "/rci/")
                    .count(),
                1
            );
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }
}
