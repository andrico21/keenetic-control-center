//! Request ids of workflow audit entries.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions establish the request-id contract"
)]
mod tests {
    use core::error::Error;
    use std::collections::BTreeSet;

    use kcc_app::{
        audit::{receipt::AuditReceipt, verify_chain},
        permissions::Permission,
        workflow::{CliChangeRequest, CliCommand, TerminalCliChangeResult},
    };
    use kcc_catalog::{Catalog, HttpMethod};
    use kcc_testkit::FaultInjection;
    use serde_json::json;

    use crate::{Fixture, description_request};

    /// Change sets begun one after another, all within a second or two.
    const SETS: usize = 12;

    /// B-20, F-25: change sets begun in the same second get distinct request ids.
    ///
    /// The entries of one set (its change and its save) share the set's id.
    // NOT cancel-safe: the fixture owns router tasks and writes.
    #[tokio::test]
    async fn change_sets_in_the_same_second_get_distinct_request_ids() -> Result<(), Box<dyn Error>>
    {
        let fixture = Fixture::spawn(FaultInjection::default()).await?;
        for index in 0..SETS {
            let mut changes = fixture.begin().await?;
            drop(
                changes
                    .apply(description_request(&format!("set-{index}")))
                    .await?,
            );
            changes.save().await?;
        }

        let entries = verify_chain(fixture.state.dir())?;
        let changes = entries
            .iter()
            .filter(|entry| entry.action == "router.change")
            .map(|entry| entry.request_id.clone())
            .collect::<Vec<_>>();
        let saves = entries
            .iter()
            .filter(|entry| entry.action == "router.save")
            .map(|entry| entry.request_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(changes.len(), SETS, "one change entry per set");
        assert_eq!(
            changes.iter().collect::<BTreeSet<_>>().len(),
            SETS,
            "distinct ids: {changes:?}"
        );
        assert_eq!(saves, changes, "a set's save carries the set's id");
        fixture.shutdown().await?;
        Ok(())
    }

    /// B-20: a change set records its entries under the caller's request id when given.
    // NOT cancel-safe: the fixture owns router tasks and writes.
    #[tokio::test]
    async fn a_change_set_takes_the_callers_request_id() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(FaultInjection::default()).await?;
        let mut changes = fixture
            .begin()
            .await?
            .with_request_id("web-caller-7".to_owned());

        let applied = changes.apply(description_request("caller")).await?;

        let AuditReceipt::Written(entry) = applied.audit else {
            return Err("the entry was not written".into());
        };
        assert_eq!(entry.request_id, "web-caller-7");
        fixture.shutdown().await?;
        Ok(())
    }

    /// B-20: a terminal change (reboot) keeps the receipt of its audit entry.
    // NOT cancel-safe: the fixture owns router tasks and writes.
    #[tokio::test]
    async fn a_terminal_change_keeps_its_audit_receipt() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(FaultInjection::default()).await?;
        let info = fixture.registry.poll_info("router").await?;
        let validated = Catalog::for_router(&info)?
            .validate("system reboot", HttpMethod::Post, &json!({}))
            .map_err(|issues| format!("catalog rejected terminal command: {issues:?}"))?;
        let request = CliChangeRequest::terminal(
            vec![CliCommand::new("system reboot".to_owned(), validated)?],
            Permission::Destructive,
            json!({"operation":"reboot"}),
        );
        let mut changes = fixture.begin().await?;

        let terminal = TerminalCliChangeResult::from(changes.apply_cli(request).await?);

        let AuditReceipt::Written(entry) = terminal.audit else {
            return Err("the terminal entry was not written".into());
        };
        assert_eq!(entry.action, "router.change_cli_terminal");
        fixture.shutdown().await?;
        Ok(())
    }
}
