//! A failed management bracket over MCP: the error code, message and audit flag of each fate
//! of the shared bracket.

#[path = "bracket_batch.rs"]
mod batch;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert wire and audit contracts"
)]
mod tests {
    use kcc_i18n::{
        bundle::{MessageKey, tr},
        keys,
        locale::Locale,
    };
    use kcc_testkit::{
        FaultInjection,
        bracket::{Fate, Recovery},
    };
    use serde_json::{Value, json};

    use crate::{
        bracket::{commands, router},
        lab::{Lab, TestResult, admin},
    };

    /// One failed bracket: router mode, tool, arguments, faults, the error code, the
    /// message, and whether the timer may still be armed.
    type Row = (
        &'static str,
        &'static str,
        Value,
        FaultInjection,
        &'static str,
        Option<MessageKey>,
        bool,
    );

    /// The failed brackets: one per shared fate, and a disarm lost in the scheduled-reboot
    /// mode.
    fn rows() -> TestResult<Vec<Row>> {
        let port = "ip http port 8430";
        let mut rows = Vec::new();
        for fate in Fate::ALL {
            let (line, code, message, armed) = match fate {
                Fate::OutcomeUnknown => (
                    port,
                    "management_outcome_unknown_fail_safe_armed",
                    Some(keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED),
                    true,
                ),
                Fate::DisarmRefused => (
                    port,
                    "management_applied_fail_safe_armed",
                    Some(keys::MANAGEMENT_DISARM_FAILED),
                    true,
                ),
                Fate::NotSent => (
                    port,
                    "management_not_sent_fail_safe_armed",
                    Some(keys::MANAGEMENT_NOT_SENT_ARMED),
                    true,
                ),
                Fate::ArmRefused => (
                    port,
                    "router_rejected",
                    Some(keys::MANAGEMENT_NOT_APPLIED),
                    false,
                ),
                Fate::WorkRefused => ("no user unused", "router_rejected", None, false),
                _ => return Err(format!("no MCP row for {fate:?}").into()),
            };
            rows.push((
                "router",
                "kcc_cli_parse",
                json!({"host":"lab-1","line":line,"confirm":true}),
                fate.faults(Recovery::FailSafeTimer, line),
                code,
                message,
                armed,
            ));
        }
        let disarm = Recovery::for_mode("extender").disarm();
        rows.push((
            "extender",
            "kcc_interfaces_write",
            json!({"host":"lab-1","op":"security_level","name":"Bridge0","level":"private","confirm":true}),
            FaultInjection::default().disconnect_before_parse(disarm.to_owned()),
            "management_applied_fail_safe_armed",
            Some(keys::MANAGEMENT_DISARM_FAILED),
            true,
        ));
        Ok(rows)
    }

    /// Each fate keeps its code and message on the wire and its flag in the audit entry;
    /// an applied change whose disarm failed is still reported unsaved.
    ///
    /// T-10: one row per shared bracket fate; the full matrix is the domain's.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn a_failed_bracket_names_the_timer_fate() -> TestResult {
        for (mode, tool, arguments, faults, code, message, armed) in rows()? {
            let lab = Lab::start(vec![("lab-1", router(mode, faults)?)], admin()).await?;

            let reply = lab.call(tool, arguments, false).await?;

            let label = format!("{mode} {tool} {code}: {reply:?}");
            assert_eq!(reply.error(), Some(code), "{label}");
            let failure = reply.failure().ok_or("expected failed tool call")?;
            let expected = message.map(|key| json!(tr(Locale::En, key, None)));
            assert_eq!(failure.get("message"), expected.as_ref(), "{label}");
            // A refused arm left no timer on the fake, though kcc cannot know that.
            let running = armed && message != Some(keys::MANAGEMENT_NOT_SENT_ARMED);
            assert_eq!(lab.router("lab-1")?.recovery_armed(), running, "{label}");
            let sent = commands(&lab)?;
            let [arm, disarm] = Recovery::for_mode(mode).lines();
            assert_eq!(sent.first().map(String::as_str), Some(arm), "{label}");
            // The lost connection takes the disarm with it.
            let lost = message == Some(keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED);
            assert_eq!(
                sent.last().map(String::as_str) == Some(disarm),
                !lost,
                "{label}"
            );
            let nothing_sent = [
                keys::MANAGEMENT_NOT_SENT_ARMED,
                keys::MANAGEMENT_NOT_APPLIED,
            ]
            .map(Some)
            .contains(&message);
            if nothing_sent {
                assert_eq!(sent, [arm, disarm], "nothing else was sent: {label}");
                let config = lab.router("lab-1")?.running_config_text();
                assert!(!config.contains("port 8430"), "{label}");
            }
            let entries = lab.audit()?;
            let action = format!("mcp.{tool}");
            let failed = entries
                .iter()
                .find(|entry| entry.action == action)
                .ok_or("missing failed change audit")?;
            assert_eq!(failed.outcome, "failed", "{label}");
            assert_eq!(
                failed.params_redacted.get("fail_safe_armed"),
                armed.then_some(&json!(true)),
                "{label}"
            );
            // The lost connection of the interface row leaves no state to read.
            if code == "management_applied_fail_safe_armed" && tool == "kcc_cli_parse" {
                let state = lab
                    .call("kcc_config_state", json!({"host":"lab-1"}), false)
                    .await?;
                assert_eq!(state.value()?.get("unsaved"), Some(&json!(true)), "{label}");
            }
            lab.stop().await?;
        }
        Ok(())
    }
}
