//! Successful MCP actions outside the change workflow are audited.
extern crate alloc;

#[path = "support/lab.rs"]
#[expect(dead_code, reason = "these tests use part of the shared MCP harness")]
mod lab;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the MCP audit contract"
)]
mod tests {
    use kcc_testkit::{FakeRouter, FaultInjection, model::Profile};
    use serde_json::{Value, json};

    use crate::lab::{Lab, TestResult, admin};

    /// One `lab-1` router built with `faults`.
    async fn lab(faults: FaultInjection) -> TestResult<Lab> {
        let router = FakeRouter::builder(Profile::default())
            .faults(faults)
            .build()?;
        Lab::start(vec![("lab-1", router)], admin()).await
    }

    /// A ping job on `lab-1`.
    fn ping() -> Value {
        json!({"host":"lab-1","op":"ping","arguments":{"host":"192.0.2.1"}})
    }

    /// E-08: a backup, a stored preset's capture and deletion, and a diagnostic start each
    /// leave one `success` entry of their tool, as the same actions do on the Web and CLI.
    // NOT cancel-safe: the fixture owns tasks until explicit shutdown.
    #[tokio::test]
    async fn actions_outside_the_change_workflow_record_their_success() -> TestResult {
        let lab = lab(FaultInjection::default()).await?;
        for (tool, arguments) in [
            ("kcc_backup_create", json!({"host":"lab-1"})),
            (
                "kcc_preset_capture",
                json!({"source":"lab-1","groups":["dns-secure"],"name":"Office"}),
            ),
            ("kcc_preset_delete", json!({"id":"office"})),
            ("kcc_diagnostics_write", ping()),
        ] {
            let reply = lab.call(tool, arguments, false).await?;
            assert_eq!(reply.error(), None, "{tool}: {reply:?}");
        }

        let recorded = lab
            .audit()?
            .into_iter()
            .filter(|entry| entry.action.starts_with("mcp."))
            .map(|entry| (entry.action, entry.outcome, entry.router))
            .collect::<Vec<_>>();
        let lab_1 = Some("lab-1".to_owned());
        let expected = [
            ("mcp.kcc_backup_create", lab_1.clone()),
            ("mcp.kcc_preset_capture", lab_1.clone()),
            ("mcp.kcc_preset_delete", None),
            ("mcp.kcc_diagnostics_write", lab_1),
        ]
        .map(|(action, router)| (action.to_owned(), "success".to_owned(), router));
        assert_eq!(recorded, expected);
        lab.stop().await
    }

    /// E-08: cancelling a running job leaves a `success` entry naming the job.
    // NOT cancel-safe: the fixture owns tasks until explicit shutdown.
    #[tokio::test]
    async fn cancelling_a_job_records_its_success() -> TestResult {
        let lab = lab(FaultInjection::default()).await?;
        let job = lab
            .jobs
            .start(
                "diagnostics.ping".to_owned(),
                Some("lab-1".to_owned()),
                false,
                async move |context| {
                    context.cancellation().cancelled().await;
                    Ok(())
                },
            )
            .await?;

        let cancelled = lab
            .call("kcc_job_cancel", json!({"id": job}), false)
            .await?;

        assert_eq!(
            cancelled.value()?.get("cancelled"),
            Some(&json!(true)),
            "{cancelled:?}"
        );
        let entry = lab
            .audit()?
            .into_iter()
            .find(|entry| entry.action == "mcp.kcc_job_cancel")
            .ok_or("job cancel not audited")?;
        assert_eq!(entry.outcome, "success");
        assert_eq!(entry.router.as_deref(), Some("lab-1"));
        assert_eq!(entry.params_redacted, json!({"id": job}));
        lab.stop().await
    }
}
