//! Interface guard refusals preserve the MCP recovery receipt.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert wire and audit contracts"
)]
mod tests {
    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_testkit::{FakeRouter, FaultInjection, model::Profile};
    use serde_json::json;

    use crate::lab::{Lab, TestResult, admin};

    /// Work refusal is unknown and armed; arm refusal has neither armed message nor flag.
    // NOT cancel-safe: the fixture may arm recovery before refusing the interface change.
    #[tokio::test]
    async fn interface_refusals_preserve_armed_outcome() -> TestResult {
        for (prefix, armed) in [
            ("interface Bridge0 security-level", true),
            ("system configuration fail-safe timer", false),
        ] {
            let fake = FakeRouter::builder(Profile::default())
                .faults(FaultInjection::default().fail_parse_matching(prefix, 1))
                .build()?;
            let lab = Lab::start(vec![("lab-1", fake)], admin()).await?;

            let reply = lab
                .call(
                    "kcc_interfaces_write",
                    json!({"host":"lab-1",
                "op":"security_level","name":"Bridge0","level":"private","confirm":true}),
                    false,
                )
                .await?;

            assert_eq!(lab.router("lab-1")?.recovery_armed(), armed);
            assert_eq!(
                reply.error(),
                Some(if armed {
                    "management_outcome_unknown_fail_safe_armed"
                } else {
                    "conflict"
                }),
                "{reply:?}"
            );
            let failure = reply.failure().ok_or("expected interface failure")?;
            assert_eq!(
                failure.get("message"),
                armed.then_some(&json!(tr(
                    Locale::En,
                    keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
                    None
                )))
            );
            let entries = lab.audit()?;
            let failed = entries
                .iter()
                .find(|entry| entry.action == "mcp.kcc_interfaces_write")
                .ok_or("missing interface refusal audit")?;
            assert_eq!(failed.outcome, "failed");
            assert_eq!(
                failed.params_redacted.get("fail_safe_armed"),
                armed.then_some(&json!(true))
            );
            lab.stop().await?;
        }
        Ok(())
    }
}
