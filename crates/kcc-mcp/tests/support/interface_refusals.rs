//! Interface refusals preserve the MCP recovery receipt.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert wire and audit contracts"
)]
mod tests {
    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_testkit::{FakeRouter, FaultInjection, bracket::Recovery, model::Profile};
    use serde_json::json;

    use crate::lab::{Lab, TestResult, admin};

    /// E-07: an unapplied interface change answers `verification_failed` with its field.
    ///
    /// The router accepted it but the read-back shows the old value, as for every other
    /// write.
    #[tokio::test]
    async fn an_unapplied_interface_change_names_its_field() -> TestResult {
        let fake = FakeRouter::builder(Profile::default())
            .faults(FaultInjection::default().silent_noop_path("parse"))
            .build()?;
        let lab = Lab::start(vec![("lab-1", fake)], admin()).await?;

        let reply = lab
            .call(
                "kcc_interfaces_write",
                json!({"host":"lab-1","op":"description","name":"Bridge0",
                    "description":"unapplied","confirm":true}),
                false,
            )
            .await?;

        assert_eq!(reply.error(), Some("verification_failed"), "{reply:?}");
        assert!(
            reply
                .failure()
                .and_then(|failure| failure.get("field"))
                .is_some_and(serde_json::Value::is_string),
            "{reply:?}"
        );
        lab.stop().await
    }

    /// Work and arm refusals close recovery when disarm remains reachable; a refused change
    /// whose disarm is refused too reports the timer as armed.
    ///
    /// E-23: a refusal whose disarm closed the timer answers `router_rejected`.
    // NOT cancel-safe: the fixture may arm recovery before refusing the interface change.
    #[tokio::test]
    async fn interface_refusals_preserve_armed_outcome() -> TestResult {
        for (faults, armed) in [
            (
                FaultInjection::default()
                    .fail_parse_matching("interface Bridge0 security-level", 1),
                false,
            ),
            (
                FaultInjection::default()
                    .fail_parse_matching("system configuration fail-safe timer", 1),
                false,
            ),
            (
                FaultInjection::default()
                    .fail_parse_matching("interface Bridge0 security-level", 1)
                    .fail_parse_matching(Recovery::FailSafeTimer.disarm(), 1),
                true,
            ),
        ] {
            let fake = FakeRouter::builder(Profile::default())
                .faults(faults)
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

            assert_eq!(lab.router("lab-1")?.recovery_armed(), armed, "{reply:?}");
            let failure = reply.failure().ok_or("expected interface failure")?;
            if armed {
                assert_eq!(
                    reply.error(),
                    Some("management_outcome_unknown_fail_safe_armed"),
                    "{reply:?}"
                );
                assert_eq!(
                    failure.get("message"),
                    Some(&json!(tr(
                        Locale::En,
                        keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
                        None
                    ))),
                    "{reply:?}"
                );
            } else {
                assert_eq!(reply.error(), Some("router_rejected"), "{reply:?}");
            }
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
