//! Batch recovery retains item outcomes on the MCP wire.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions establish the wire contract"
)]
mod tests {
    use std::io::{self, Write as _};

    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
    use serde_json::json;

    use crate::lab::{Lab, TestResult, admin};

    /// Cleanup cannot replace per-item outcomes or infer application from HTTP success.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn batch_completion_controls_recovery_message() -> TestResult {
        for mode in ["router", "extender"] {
            for (refused, partial, armed) in [
                (true, false, true),
                (false, false, true),
                (true, true, true),
                (true, false, false),
            ] {
                let mut scenario = migration::Fixture::default();
                scenario.mode = Some(mode.to_owned());
                let mut faults = FaultInjection::default();
                if refused {
                    faults = faults.refuse_batch_pointer("/ip/http/port".to_owned());
                }
                if armed {
                    faults = faults.fail_parse_matching("no system", 1);
                }
                let fake = FakeRouter::builder(Profile::default())
                    .faults(faults)
                    .build()?
                    .with_migration(scenario);
                let lab = Lab::start(vec![("lab-1", fake)], admin()).await?;
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
                let applied = !refused;
                let (code, key) = if applied {
                    (
                        "management_applied_fail_safe_armed",
                        keys::MANAGEMENT_DISARM_FAILED,
                    )
                } else {
                    (
                        "management_outcome_unknown_fail_safe_armed",
                        keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
                    )
                };
                assert_eq!(reply.error(), armed.then_some(code), "{mode}: {reply:?}");
                let value = if armed {
                    reply.failure().ok_or("recovery error")?
                } else {
                    reply.value()?
                };
                assert_eq!(
                    value.pointer("/responses/0/ok"),
                    Some(&json!(!refused)),
                    "{reply:?}"
                );
                if refused {
                    assert_eq!(
                        value.pointer("/responses/0/error"),
                        Some(&json!("router_rejected"))
                    );
                }
                assert_eq!(
                    value.get("message"),
                    armed.then(|| json!(tr(Locale::En, key, None))).as_ref()
                );
                assert_eq!(lab.router("lab-1")?.recovery_armed(), armed);
                let entries = lab.audit()?;
                let batch = entries
                    .iter()
                    .find(|entry| entry.action == "router.change_batch")
                    .ok_or("batch audit")?;
                let outcome = if partial {
                    "partially_applied_unsaved"
                } else if refused {
                    "failed"
                } else {
                    "applied_unsaved"
                };
                assert_eq!(batch.outcome, outcome);
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
                writeln!(
                    io::stderr(),
                    "T112 MCP mode={mode} refused={refused} partial={partial} key={} code={} audit={outcome} armed={armed} fake={armed}",
                    if armed { key.id() } else { "none" },
                    reply.error().unwrap_or("none")
                )?;
                lab.stop().await?;
            }
        }
        Ok(())
    }
}
