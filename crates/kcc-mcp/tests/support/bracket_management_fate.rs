//! The MCP batch error names whether a management item actually succeeded.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions establish the wire contract"
)]
mod tests {
    use kcc_app::audit::AuditEntry;
    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
    use serde_json::json;

    use crate::lab::{Lab, TestResult, admin};

    /// An accepted ordinary sibling cannot turn a refused management item into applied.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn refused_management_item_reports_unknown_armed() -> TestResult {
        for mode in ["router", "extender"] {
            let mut scenario = migration::Fixture::default();
            scenario.mode = Some(mode.to_owned());
            let faults = FaultInjection::default()
                .refuse_batch_pointer("/ip/http/port".to_owned())
                .fail_parse_matching("no system", 1);
            let fake = FakeRouter::builder(Profile::default())
                .faults(faults)
                .build()?
                .with_migration(scenario);
            let lab = Lab::start(vec![("lab-1", fake)], admin()).await?;

            let reply = lab
                .call(
                    "kcc_rci_batch",
                    json!({
                        "host":"lab-1",
                        "confirm":true,
                        "items":[
                            {"ip":{"http":{"port":{"port":8431_u16}}}},
                            {"system":{"description":{"description":"ordinary"}}}
                        ]
                    }),
                    false,
                )
                .await?;

            assert_eq!(
                reply.error(),
                Some("management_outcome_unknown_fail_safe_armed"),
                "{mode}: {reply:?}"
            );
            let failure = reply.failure().ok_or("recovery error")?;
            assert_eq!(failure.pointer("/responses/0/ok"), Some(&json!(false)));
            assert_eq!(failure.pointer("/responses/1/ok"), Some(&json!(true)));
            assert_eq!(
                failure.get("message"),
                Some(&json!(tr(
                    Locale::En,
                    keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
                    None
                )))
            );
            assert!(lab.router("lab-1")?.recovery_armed());
            let entries = lab.audit()?;
            let failed: &AuditEntry = entries
                .iter()
                .find(|entry| entry.action == "mcp.kcc_rci_batch")
                .ok_or("MCP audit")?;
            assert_eq!(
                failed.params_redacted.get("fail_safe_armed"),
                Some(&json!(true))
            );
            lab.stop().await?;
        }
        Ok(())
    }
}
