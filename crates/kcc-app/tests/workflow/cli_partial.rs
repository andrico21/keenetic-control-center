//! A CLI batch the router refuses part of still records the lines it applied.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions establish the partial CLI batch receipt"
)]
mod tests {
    use core::error::Error;

    use kcc_app::{
        audit::read_entries,
        permissions::Permission,
        workflow::{CliChangeRequest, CliCommand, WorkflowError},
    };
    use kcc_catalog::{Catalog, HttpMethod};
    use kcc_testkit::FaultInjection;
    use serde_json::json;

    use crate::Fixture;

    /// N2: a CLI batch whose second line the router refuses fails, and its one
    /// `router.change_cli` entry records the applied line with the failed/applied counts,
    /// like a root batch.
    // NOT cancel-safe: the fixture owns router tasks and writes.
    #[tokio::test]
    async fn a_partly_refused_cli_batch_records_its_applied_lines() -> Result<(), Box<dyn Error>> {
        let fixture =
            Fixture::spawn(FaultInjection::default().fail_parse_matching("description", 1)).await?;
        let info = fixture.registry.poll_info("router").await?;
        let catalog = Catalog::for_router(&info)?;
        let commands = [
            (
                "system country DE",
                "system country",
                json!({"country":"DE"}),
            ),
            (
                "system description refused",
                "system description",
                json!({"description":"refused"}),
            ),
        ]
        .into_iter()
        .map(|(line, path, value)| {
            let validated = catalog
                .validate(path, HttpMethod::Post, &value)
                .map_err(|issues| format!("catalog rejected fixture command: {issues:?}"))?;
            CliCommand::new(line.to_owned(), validated).map_err(|error| format!("{line}: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
        let mut changes = fixture.begin(None).await?;

        let result = changes
            .apply_cli(CliChangeRequest::new(
                commands,
                Vec::new(),
                Permission::Write,
                json!({"validated":true}),
            ))
            .await;

        assert!(matches!(result, Err(WorkflowError::Rci(_))), "{result:?}");
        let entries = read_entries(&fixture.directory.path().join("state"))?
            .into_iter()
            .filter(|entry| entry.action == "router.change_cli")
            .collect::<Vec<_>>();
        let [entry] = entries.as_slice() else {
            return Err(format!("one partial CLI entry expected: {entries:?}").into());
        };
        assert_eq!(entry.outcome, "partially_applied_persisted");
        assert_eq!(
            entry.params_redacted,
            json!({"error":"router_rejected","succeeded":1_usize,"failed":1_usize})
        );
        drop(changes);
        fixture.shutdown().await?;
        Ok(())
    }
}
