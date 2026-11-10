//! Nested destructive requests cannot bypass MCP authorization.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the MCP security boundary"
)]
mod tests {
    use kcc_app::permissions::{Permission, Role};
    use kcc_testkit::{FakeRouter, model::Profile};
    use serde_json::json;

    use crate::lab::{Lab, TestResult, admin};

    /// Management changes require confirmation and run inside the same recovery timer.
    // NOT cancel-safe: the fixture owns router and MCP tasks until shutdown.
    #[tokio::test]
    async fn nested_management_is_confirmed_and_bracketed() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let input = json!({"host":"lab-1","items":[{"ip":{"http":{"port":{"port":8082_u16}}}}]});
        let before = lab.requests("lab-1")?;
        let refused = lab.call("kcc_rci_batch", input.clone(), false).await?;
        assert_eq!(refused.error(), Some("confirm_required"));
        assert_eq!(lab.requests("lab-1")?, before);
        let mut confirmed = input;
        drop(
            confirmed
                .as_object_mut()
                .ok_or("input object")?
                .insert("confirm".to_owned(), json!(true)),
        );
        let reply = lab.call("kcc_rci_batch", confirmed, false).await?;
        assert_eq!(reply.error(), None);
        let timers = lab
            .router("lab-1")?
            .request_log()
            .iter()
            .filter_map(|record| {
                record
                    .command()
                    .filter(|line| {
                        let command = line.strip_prefix("no ").unwrap_or(line);
                        command.starts_with("system configuration fail-safe timer")
                            || command.starts_with("system reboot")
                    })
                    .map(str::to_owned)
            })
            .collect::<Vec<_>>();
        assert_eq!(timers.len(), 2, "arm and disarm: {timers:?}");
        lab.stop().await
    }

    /// Disabled destructive operations are rejected before even discovering the router.
    // NOT cancel-safe: the fixture owns tasks until explicit shutdown.
    #[tokio::test]
    async fn nested_destructive_requests_are_refused_without_router_access() -> TestResult {
        for (tool, input) in [
            (
                "kcc_rci_execute",
                json!({"host":"lab-1","catalog_path":"system reboot","path":["system","reboot"],"value":{}}),
            ),
            (
                "kcc_rci_execute",
                json!({"host":"lab-1","catalog_path":"system","path":["system"],"value":{"reboot":{}}}),
            ),
            (
                "kcc_rci_batch",
                json!({"host":"lab-1","items":[{"system":{"configuration":{"factory-reset":{}}}}]}),
            ),
        ] {
            let lab = Lab::start_with_destructive(
                vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
                admin(),
                false,
            )
            .await?;
            let before = lab.requests("lab-1")?;
            let reply = lab.call(tool, input, false).await?;
            assert_eq!(reply.error(), Some("destructive_disabled"), "{tool}");
            assert_eq!(
                lab.requests("lab-1")?,
                before,
                "{tool}: zero router requests"
            );
            lab.stop().await?;
        }
        Ok(())
    }

    /// Explicit confirmation cannot replace the destructive permission.
    // NOT cancel-safe: the fixture owns tasks until explicit shutdown.
    #[tokio::test]
    async fn nested_destructive_requires_role_permission() -> TestResult {
        let role = Role::new(
            "raw-writer".to_owned(),
            [Permission::Read, Permission::Write, Permission::RawRci],
            vec!["*".to_owned()],
        );
        let lab = Lab::start_with_destructive(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            role,
            true,
        )
        .await?;
        let before = lab.requests("lab-1")?;
        let reply = lab
            .call(
                "kcc_rci_execute",
                json!({
                    "host":"lab-1","catalog_path":"system","path":["system"],
                    "value":{"reboot":{}},"confirm":true
                }),
                false,
            )
            .await?;
        assert_eq!(reply.error(), Some("forbidden"));
        assert_eq!(lab.requests("lab-1")?, before);
        lab.stop().await
    }

    /// Authorized nested actions still reach the workflow and receive a change receipt.
    // NOT cancel-safe: the fixture owns tasks until explicit shutdown.
    #[tokio::test]
    async fn confirmed_nested_destructive_is_applied_and_audited() -> TestResult {
        let lab = Lab::start_with_destructive(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
            true,
        )
        .await?;
        let reply = lab
            .call(
                "kcc_rci_execute",
                json!({
                    "host":"lab-1","catalog_path":"system","path":["system"],
                    "value":{"reboot":{}},"confirm":true
                }),
                false,
            )
            .await?;
        assert_eq!(reply.error(), None);
        assert_eq!(reply.value()?.get("unsaved"), Some(&json!(true)));
        assert!(
            lab.audit()?
                .iter()
                .any(|entry| entry.action == "router.change" && entry.outcome == "applied_unsaved")
        );
        lab.stop().await
    }

    /// Raw delete input accepted by the catalog.
    fn delete_input(confirm: bool) -> serde_json::Value {
        json!({
            "host":"lab-1","catalog_path":"ip hotspot host","path":["ip","hotspot","host"],
            "value":{"mac":"02:00:00:00:11:01"},"confirm":confirm
        })
    }

    /// Explicit confirmation cannot replace the destructive permission for raw delete.
    // NOT cancel-safe: the fixture owns tasks until explicit shutdown.
    #[tokio::test]
    async fn raw_delete_requires_role_permission() -> TestResult {
        let role = Role::new(
            "raw-writer".to_owned(),
            [Permission::Read, Permission::Write, Permission::RawRci],
            vec!["*".to_owned()],
        );
        let lab = Lab::start_with_destructive(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            role,
            true,
        )
        .await?;
        let before = lab.requests("lab-1")?;
        let reply = lab
            .call("kcc_rci_delete", delete_input(true), false)
            .await?;
        assert_eq!(reply.error(), Some("forbidden"));
        assert_eq!(lab.requests("lab-1")?, before);
        lab.stop().await
    }

    /// An authorized, confirmed raw delete reaches the workflow and is audited.
    // NOT cancel-safe: the fixture owns tasks until explicit shutdown.
    #[tokio::test]
    async fn confirmed_raw_delete_is_applied_and_audited() -> TestResult {
        let lab = Lab::start_with_destructive(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
            true,
        )
        .await?;
        let reply = lab
            .call("kcc_rci_delete", delete_input(true), false)
            .await?;
        assert_eq!(reply.error(), None);
        assert!(
            lab.audit()?
                .iter()
                .any(|entry| entry.action == "router.change_delete"
                    && entry.outcome == "applied_unsaved")
        );
        lab.stop().await
    }

    /// Raw delete is refused without router access while destructive calls are disabled.
    // NOT cancel-safe: the fixture owns tasks until explicit shutdown.
    #[tokio::test]
    async fn raw_delete_refused_when_destructive_disabled() -> TestResult {
        let lab = Lab::start_with_destructive(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
            false,
        )
        .await?;
        let before = lab.requests("lab-1")?;
        let reply = lab
            .call("kcc_rci_delete", delete_input(true), false)
            .await?;
        assert_eq!(reply.error(), Some("destructive_disabled"));
        assert_eq!(lab.requests("lab-1")?, before);
        lab.stop().await
    }
}
