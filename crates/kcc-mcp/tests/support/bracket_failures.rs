//! Recovery outcomes across the MCP wire and audit boundary.

#[path = "bracket_authority.rs"]
mod authority;
#[path = "bracket_batch.rs"]
mod batch;
#[path = "bracket_management_fate.rs"]
mod management_fate;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert wire and audit contracts"
)]
mod tests {
    use std::io::{self, Write as _};

    use kcc_i18n::{
        bundle::{MessageKey, tr},
        keys,
        locale::Locale,
    };
    use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
    use serde_json::json;

    use crate::lab::{Lab, TestResult, admin};

    /// Exercises the real MCP adapter with both recovery modes.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    async fn check(
        faults: FaultInjection,
        line: &str,
        expected: (&str, Option<MessageKey>),
    ) -> TestResult {
        for mode in ["router", "extender"] {
            let mut scenario = migration::Fixture::default();
            scenario.mode = Some(mode.to_owned());
            let fake = FakeRouter::builder(Profile::default())
                .faults(faults.clone())
                .build()?
                .with_migration(scenario);
            let lab = Lab::start(vec![("lab-1", fake)], admin()).await?;
            let reply = lab
                .call(
                    "kcc_cli_parse",
                    json!({"host":"lab-1","line":line,"confirm":true}),
                    false,
                )
                .await?;
            let armed = expected.1.is_some();
            assert_eq!(
                lab.router("lab-1")?.recovery_armed(),
                armed,
                "{mode}: fake recovery state"
            );
            assert_eq!(reply.error(), Some(expected.0), "{mode}: {reply:?}");
            let failure = reply.failure().ok_or("expected failed tool call")?;
            if let Some(key) = expected.1 {
                assert_eq!(
                    failure.get("message"),
                    Some(&json!(tr(Locale::En, key, None))),
                    "{mode}: {reply:?}"
                );
            } else {
                assert_eq!(failure.get("message"), None, "no armed note after disarm");
            }
            let entries = lab.audit()?;
            let failed = entries
                .iter()
                .find(|entry| entry.action == "mcp.kcc_cli_parse")
                .ok_or("missing failed change audit")?;
            assert_eq!(failed.outcome, "failed");
            assert_eq!(
                failed.params_redacted.get("fail_safe_armed"),
                armed.then_some(&json!(true)),
                "{mode}: {failed:?}"
            );
            writeln!(
                io::stderr(),
                "RECOVERY MCP {mode} {line}: code={} key={} audit={armed} fake={armed}",
                expected.0,
                expected.1.map_or("none", MessageKey::id)
            )?;
            lab.stop().await?;
        }
        Ok(())
    }

    /// Lost response keeps the unknown outcome and armed recovery on the wire.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn lost_change_reports_armed() -> TestResult {
        check(
            FaultInjection::default().disconnect_after_parse("ip http port".to_owned()),
            "ip http port 8430",
            (
                "management_outcome_unknown_fail_safe_armed",
                Some(keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED),
            ),
        )
        .await
    }

    /// A known applied mutation reports failed recovery cleanup.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn applied_change_reports_armed() -> TestResult {
        check(
            FaultInjection::default().fail_parse_matching("no system", 1),
            "ip http port 8430",
            (
                "management_applied_fail_safe_armed",
                Some(keys::MANAGEMENT_DISARM_FAILED),
            ),
        )
        .await
    }

    /// Refusing the work and cleanup cannot erase armed recovery.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn refused_change_and_disarm_reports_armed() -> TestResult {
        check(
            FaultInjection::default().fail_parse_matching("no ", 2),
            "no user unused",
            (
                "management_outcome_unknown_fail_safe_armed",
                Some(keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED),
            ),
        )
        .await
    }

    /// Successful cleanup preserves the work refusal code.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn refused_change_disarmed_preserves_error() -> TestResult {
        check(
            FaultInjection::default().fail_parse_matching("no ", 1),
            "no user unused",
            ("router_rejected", None),
        )
        .await
    }

    /// A refused arm says nothing else was sent: with its disarm refused too, that the timer
    /// may be armed; with its disarm accepted, the router's refusal and that the timer is off.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn refused_arm_reports_nothing_sent() -> TestResult {
        let rows = [
            (
                2,
                "management_not_sent_fail_safe_armed",
                keys::MANAGEMENT_NOT_SENT_ARMED,
            ),
            (1, "router_rejected", keys::MANAGEMENT_NOT_APPLIED),
        ];
        for (mode, timer) in [
            ("router", "system configuration fail-safe timer"),
            ("extender", "system reboot"),
        ] {
            for (refusals, code, key) in rows {
                let mut scenario = migration::Fixture::default();
                scenario.mode = Some(mode.to_owned());
                let fake = FakeRouter::builder(Profile::default())
                    .faults(FaultInjection::default().fail_parse_matching(timer, refusals))
                    .build()?
                    .with_migration(scenario);
                let lab = Lab::start(vec![("lab-1", fake)], admin()).await?;
                let reply = lab
                    .call(
                        "kcc_cli_parse",
                        json!({"host":"lab-1","line":"ip http port 8082","confirm":true}),
                        false,
                    )
                    .await?;
                let label = format!("{mode} refusals={refusals}: {reply:?}");
                assert_eq!(reply.error(), Some(code), "{label}");
                assert_eq!(
                    reply.failure().and_then(|failure| failure.get("message")),
                    Some(&json!(tr(Locale::En, key, None))),
                    "{label}"
                );
                let router = lab.router("lab-1")?;
                let commands = router
                    .request_log()
                    .iter()
                    .filter_map(|record| record.command().map(str::to_owned))
                    .collect::<Vec<_>>();
                assert_eq!(commands.len(), 2, "arm and disarm only: {commands:?}");
                assert!(
                    commands.iter().all(|line| line.contains(timer)),
                    "{commands:?}"
                );
                assert!(!router.running_config_text().contains("port 8082"));
                let entries = lab.audit()?;
                let failed = entries
                    .iter()
                    .find(|entry| entry.action == "mcp.kcc_cli_parse")
                    .ok_or("missing failed change audit")?;
                assert_eq!(
                    failed.params_redacted.get("fail_safe_armed"),
                    (refusals == 2).then_some(&json!(true)),
                    "{label}: {failed:?}"
                );
                lab.stop().await?;
            }
        }
        Ok(())
    }

    /// Curated interface cleanup exposes armed native recovery in either router mode.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn interface_disarm_failure_reports_armed() -> TestResult {
        for mode in ["router", "extender"] {
            for faults in [
                FaultInjection::default().fail_parse_matching("no system", 1),
                FaultInjection::default().disconnect_before_parse("no system".to_owned()),
            ] {
                let mut scenario = migration::Fixture::default();
                scenario.mode = Some(mode.to_owned());
                let fake = FakeRouter::builder(Profile::default())
                    .faults(faults)
                    .build()?
                    .with_migration(scenario);
                let lab = Lab::start(vec![("lab-1", fake)], admin()).await?;
                let reply = lab.call("kcc_interfaces_write", json!({"host":"lab-1","op":"security_level","name":"Bridge0","level":"private","confirm":true}), false).await?;
                assert!(
                    lab.router("lab-1")?.recovery_armed(),
                    "{mode}: timer remains armed"
                );
                assert_eq!(
                    reply.error(),
                    Some("management_applied_fail_safe_armed"),
                    "{mode}: {reply:?}"
                );
                assert_eq!(
                    reply.failure().and_then(|value| value.get("message")),
                    Some(&json!(tr(Locale::En, keys::MANAGEMENT_DISARM_FAILED, None)))
                );
                let (arm, disarm) = if mode == "router" {
                    (
                        "system configuration fail-safe timer reboot 300",
                        "no system configuration fail-safe timer",
                    )
                } else {
                    ("system reboot 300", "no system reboot")
                };
                let commands = lab
                    .router("lab-1")?
                    .request_log()
                    .iter()
                    .filter_map(|record| record.command().map(str::to_owned))
                    .collect::<Vec<_>>();
                assert_eq!(
                    (
                        commands.first().map(String::as_str),
                        commands.last().map(String::as_str)
                    ),
                    (Some(arm), Some(disarm)),
                    "{mode}: the recovery of the router's mode: {commands:?}"
                );
                let entries = lab.audit()?;
                let failed = entries
                    .iter()
                    .find(|entry| entry.action == "mcp.kcc_interfaces_write")
                    .ok_or("missing failed change audit")?;
                assert_eq!(
                    failed.params_redacted.get("fail_safe_armed"),
                    Some(&json!(true))
                );
                writeln!(
                    io::stderr(),
                    "RECOVERY MCP interface {mode}: code=management_applied_fail_safe_armed key=management-disarm-failed audit=true fake=true"
                )?;
                lab.stop().await?;
            }
        }
        Ok(())
    }
}
