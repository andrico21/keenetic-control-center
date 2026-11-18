//! Batch recovery keeps item outcomes on the MCP wire.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions establish the wire contract"
)]
mod tests {
    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_testkit::{FaultInjection, bracket::Recovery};
    use serde_json::json;

    use crate::{
        bracket::router,
        lab::{Lab, TestResult, admin},
    };

    /// Cleanup cannot replace per-item outcomes or infer application from HTTP success; an
    /// accepted ordinary sibling never makes a refused management item applied.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn batch_completion_controls_recovery_message() -> TestResult {
        for (refused, partial, armed) in [
            (true, false, true),
            (false, false, true),
            (true, true, true),
            (true, false, false),
        ] {
            let mut faults = FaultInjection::default();
            if refused {
                faults = faults.refuse_batch_pointer("/ip/http/port".to_owned());
            }
            if armed {
                faults = faults.fail_parse_matching(Recovery::FailSafeTimer.disarm(), 1);
            }
            let lab = Lab::start(vec![("lab-1", router("router", faults)?)], admin()).await?;
            let mut items = vec![json!({"ip":{"http":{"port":{"port":8430_u16}}}})];
            if partial {
                items.push(json!({"system":{"description":{"description":"lab"}}}));
            }
            let reply = lab
                .call(
                    "kcc_rci_batch",
                    json!({"host":"lab-1","items":items,"confirm":true}),
                    false,
                )
                .await?;
            let label = format!("refused={refused} partial={partial} armed={armed}: {reply:?}");
            let (code, key) = if refused {
                (
                    "management_outcome_unknown_fail_safe_armed",
                    keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
                )
            } else {
                (
                    "management_applied_fail_safe_armed",
                    keys::MANAGEMENT_DISARM_FAILED,
                )
            };
            assert_eq!(reply.error(), armed.then_some(code), "{label}");
            let value = if armed {
                reply.failure().ok_or("recovery error")?
            } else {
                reply.value()?
            };
            assert_eq!(value.pointer("/responses/0/ok"), Some(&json!(!refused)));
            assert_eq!(
                value.pointer("/responses/1/ok"),
                partial.then_some(&json!(true)),
                "{label}"
            );
            if refused {
                assert_eq!(
                    value.pointer("/responses/0/error"),
                    Some(&json!("router_rejected"))
                );
            }
            assert_eq!(
                value.get("message"),
                armed.then(|| json!(tr(Locale::En, key, None))).as_ref(),
                "{label}"
            );
            assert_eq!(lab.router("lab-1")?.recovery_armed(), armed, "{label}");
            let entries = lab.audit()?;
            let batch = entries
                .iter()
                .find(|entry| entry.action == "router.change_batch")
                .ok_or("batch audit")?;
            let outcome = match (partial, refused) {
                (true, _) => "partially_applied_unsaved",
                (false, true) => "failed",
                (false, false) => "applied_unsaved",
            };
            assert_eq!(batch.outcome, outcome, "{label}");
            if armed {
                let entry = entries
                    .iter()
                    .find(|entry| entry.action == "mcp.kcc_rci_batch")
                    .ok_or("MCP audit")?;
                assert_eq!(
                    entry.params_redacted.get("fail_safe_armed"),
                    Some(&json!(true))
                );
            }
            lab.stop().await?;
        }
        Ok(())
    }
}
