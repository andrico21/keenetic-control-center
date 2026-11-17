//! A batch that stops part-way is audited for the chunks the router applied.
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
        workflow::{BatchChangeRequest, BatchItem, WorkflowError},
    };
    use kcc_rci::RciError;
    use kcc_testkit::FaultInjection;
    use serde_json::json;

    use crate::Fixture;

    /// A-04: when a later chunk fails, the chunks the router already applied are audited as
    /// a partial change and the request error is returned.
    // NOT cancel-safe: the fixture owns router tasks and writes.
    #[tokio::test]
    async fn a_later_chunk_failure_audits_the_applied_chunks() -> Result<(), Box<dyn Error>> {
        let fixture =
            Fixture::spawn(FaultInjection::default().fail_read_matching("second-chunk-marker", 1))
                .await?;
        let filler = "x".repeat(600 * 1024);
        let items = [
            json!({"system":{"description":{"description":filler}}}),
            json!({"system":{"description":{"description":format!("{filler}second-chunk-marker")}}}),
        ]
        .into_iter()
        .map(BatchItem::new)
        .collect();
        let mut changes = fixture.begin().await?;

        let result = changes
            .apply_batch(BatchChangeRequest::new(
                items,
                Vec::new(),
                Permission::Write,
                json!({"validated":true}),
            ))
            .await;

        assert!(
            matches!(
                result,
                Err(WorkflowError::Rci(RciError::Http { status: 500 }))
            ),
            "{result:?}"
        );
        let entries = read_entries(&fixture.directory.path().join("state"))?;
        let entry = entries
            .iter()
            .find(|entry| entry.action == "router.change_batch")
            .ok_or("the applied first chunk is audited")?;
        assert_eq!(entry.outcome, "partially_applied_unsaved");
        assert_eq!(
            entry.params_redacted,
            json!({"error":"request_failed","succeeded":1_usize,"failed":0_usize,"unanswered":1_usize})
        );
        drop(changes);
        fixture.shutdown().await?;
        Ok(())
    }

    /// A-04: a batch reply shorter than the batch is an error, never a smaller success.
    // NOT cancel-safe: the fixture owns router tasks and writes.
    #[tokio::test]
    async fn a_short_batch_reply_is_not_a_success() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(FaultInjection::default().short_batch_reply()).await?;
        let items = [
            json!({"system":{"description":{"description":"lab"}}}),
            json!({"system":{"country":{"country":"DE"}}}),
        ]
        .into_iter()
        .map(BatchItem::new)
        .collect();
        let mut changes = fixture.begin().await?;

        let result = changes
            .apply_batch(BatchChangeRequest::new(
                items,
                Vec::new(),
                Permission::Write,
                json!({"validated":true}),
            ))
            .await;

        assert!(
            matches!(result, Err(WorkflowError::Rci(RciError::Decode))),
            "{result:?}"
        );
        drop(changes);
        fixture.shutdown().await?;
        Ok(())
    }
}
