//! CLI lines outside the catalog through the MCP raw escape.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the raw security boundary"
)]
mod tests {
    use kcc_app::permissions::{Permission, Role};
    use kcc_testkit::{FakeRouter, model::Profile};
    use serde_json::json;

    use crate::lab::{Lab, TestResult, admin};

    /// The line no catalog maps; only the raw escape can send it.
    const LINE: &str = "frobnicate the router";

    /// E-22: an unvalidated line is destructive.
    ///
    /// A role allowed the raw escape but not `Destructive` is refused, and an administrator
    /// needs `confirm`; nothing reaches the router until both hold. Then the line is sent,
    /// and the fake router, which knows no such command, rejects it.
    // NOT cancel-safe: the fixture owns router and MCP tasks until explicit shutdown.
    #[tokio::test]
    async fn an_unvalidated_line_needs_destructive_and_confirm() -> TestResult {
        let escape_only = Role::new(
            "raw-admin".to_owned(),
            [
                Permission::Read,
                Permission::Write,
                Permission::RawRci,
                Permission::ManageRouters,
            ],
            vec!["*".to_owned()],
        );
        for (role, confirm, expected, sends) in [
            (escape_only, true, "forbidden", false),
            (admin(), false, "confirm_required", false),
            (admin(), true, "router_rejected", true),
        ] {
            let lab = Lab::start(
                vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
                role,
            )
            .await?;
            let before = lab.requests("lab-1")?;
            let reply = lab
                .call(
                    "kcc_cli_parse",
                    json!({"host":"lab-1","line":LINE,"confirm":confirm}),
                    false,
                )
                .await?;
            let sent = lab.requests("lab-1")? > before;
            assert_eq!(reply.error(), Some(expected), "{confirm}: {reply:?}");
            assert_eq!(sent, sends, "{confirm}");
            lab.stop().await?;
        }
        Ok(())
    }
}
