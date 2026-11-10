//! Registry-driven raw authorization and firmware compatibility contracts.
#[cfg(test)]
#[path = "raw_parity/gate_matrix.rs"]
mod gate_matrix;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the raw security boundary"
)]
mod tests {
    use kcc_mcp::registry::definitions::tools;
    use kcc_testkit::{
        FakeRouter,
        model::{Firmware, Model, Profile},
    };
    use serde_json::{Value, json};

    use crate::lab::{Lab, TestResult, admin};

    /// Actual cases driven through every gate; registry growth must extend this matrix.
    pub(super) fn cases(confirm: bool) -> Vec<(&'static str, Value)> {
        vec![
            (
                "kcc_rci_execute",
                json!({"host":"lab-1","catalog_path":"system","path":["system"],"value":{"reboot":{}},"confirm":confirm}),
            ),
            (
                "kcc_rci_delete",
                json!({"host":"lab-1","catalog_path":"ip hotspot host","path":["ip","hotspot","host"],"value":{"mac":"02:00:00:00:11:01"},"confirm":confirm}),
            ),
            (
                "kcc_rci_batch",
                json!({"host":"lab-1","items":[{"system reboot":{}}],"confirm":confirm}),
            ),
            (
                "kcc_cli_parse",
                json!({"host":"lab-1","line":"components commit","confirm":confirm}),
            ),
        ]
    }

    /// Management and unvalidated CLI lines are gated before discovery too.
    // NOT cancel-safe: the fixture owns router and session tasks until shutdown.
    #[tokio::test]
    async fn management_cli_refusals_precede_discovery() -> TestResult {
        for line in ["ip http port 8082", "SYSTEM REBOOT"] {
            for (confirm, enabled, expected) in [
                (false, true, "confirm_required"),
                (true, false, "destructive_disabled"),
            ] {
                let lab = Lab::start_with_destructive(
                    vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
                    admin(),
                    enabled,
                )
                .await?;
                let before = lab.requests("lab-1")?;
                let reply = lab
                    .call(
                        "kcc_cli_parse",
                        json!({"host":"lab-1","line":line,"confirm":confirm}),
                        false,
                    )
                    .await?;
                assert_eq!(reply.error(), Some(expected), "{line}");
                assert_eq!(lab.requests("lab-1")?, before);
                lab.stop().await?;
            }
        }
        Ok(())
    }

    /// Every registered mutating raw tool must execute the same parity cases.
    #[test]
    fn registered_mutating_raw_tools_have_gate_cases() {
        let mut registered = tools()
            .into_iter()
            .filter(|tool| tool.toolset == "raw" && !tool.read_only)
            .map(|tool| tool.name)
            .collect::<Vec<_>>();
        let mut covered = cases(true)
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>();
        registered.sort_unstable();
        covered.sort_unstable();
        assert_eq!(registered, covered);
    }

    /// Whole-key and negative requests cannot use lower-risk raw spellings.
    // NOT cancel-safe: the fixture owns router and session tasks until shutdown.
    #[tokio::test]
    async fn raw_spellings_are_refused_without_requests() -> TestResult {
        let lab = Lab::start_with_destructive(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
            false,
        )
        .await?;
        for (tool, input) in [
            (
                "kcc_rci_batch",
                json!({"host":"lab-1","items":[{"system reboot":{}}]}),
            ),
            (
                "kcc_rci_batch",
                json!({"host":"lab-1","items":[{"user":{"name":"victim","no":true}}]}),
            ),
            (
                "kcc_cli_parse",
                json!({"host":"lab-1","line":"no user victim"}),
            ),
            (
                "kcc_rci_execute",
                json!({"host":"lab-1","catalog_path":"interface esim profile delete","path":["interface","esim","profile","delete"],"value":{}}),
            ),
        ] {
            let before = lab.requests("lab-1")?;
            let reply = lab.call(tool, input, false).await?;
            assert_eq!(reply.error(), Some("destructive_disabled"), "{tool}");
            assert_eq!(lab.requests("lab-1")?, before);
        }
        lab.stop().await
    }

    /// Valid older-only requests survive the preliminary catalog selection on each tool.
    // NOT cancel-safe: the fixture owns router and session tasks until shutdown.
    #[tokio::test]
    async fn older_catalog_commands_work_through_raw_tools() -> TestResult {
        for firmware in [Firmware::V4_3, Firmware::V5_0] {
            let (path, words, body) = if firmware == Firmware::V4_3 {
                (
                    "cifs master",
                    json!(["cifs", "master"]),
                    json!({"cifs":{"master":{}}}),
                )
            } else {
                (
                    "kabinet port",
                    json!(["kabinet", "port"]),
                    json!({"kabinet":{"port":{}}}),
                )
            };
            for (tool, input) in [
                (
                    "kcc_rci_execute",
                    json!({"host":"lab-1","catalog_path":path,"path":words,"value":{}}),
                ),
                (
                    "kcc_rci_delete",
                    json!({"host":"lab-1","catalog_path":path,"path":words,"value":{},"confirm":true}),
                ),
                ("kcc_rci_batch", json!({"host":"lab-1","items":[body]})),
            ] {
                let profile = Profile::new(Model::Kn1811, firmware)?;
                let lab = Lab::start(
                    vec![("lab-1", FakeRouter::builder(profile).build()?)],
                    admin(),
                )
                .await?;
                let reply = lab.call(tool, input, false).await?;
                assert_eq!(reply.error(), None, "{tool} {firmware}");
                assert!(
                    lab.router("lab-1")?
                        .request_log()
                        .iter()
                        .any(|request| request.path().starts_with("/rci")
                            && matches!(request.method().as_str(), "POST" | "DELETE"))
                );
                lab.stop().await?;
            }
        }
        Ok(())
    }

    /// Confirmed CLI and mixed raw writes both arm and cancel management recovery.
    // NOT cancel-safe: the fixture owns router and session tasks until shutdown.
    #[tokio::test]
    async fn cli_and_mixed_requests_arm_and_disarm_recovery() -> TestResult {
        for (tool, input) in [
            (
                "kcc_cli_parse",
                json!({"host":"lab-1","line":"ip http port 8082","confirm":true}),
            ),
            (
                "kcc_rci_batch",
                json!({"host":"lab-1","items":[{"ip":{"http":{"port":{"port":8082_u16}}}},{"mws":{"member":{"reboot":{}}}}],"confirm":true}),
            ),
        ] {
            let lab = Lab::start(
                vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
                admin(),
            )
            .await?;
            let reply = lab.call(tool, input, false).await?;
            assert_eq!(reply.error(), None, "{tool}");
            let log = lab.router("lab-1")?.request_log();
            let timers = log
                .iter()
                .filter_map(|record| record.command())
                .filter(|line| {
                    let command = line.strip_prefix("no ").unwrap_or(line);
                    command.starts_with("system configuration fail-safe timer")
                        || command.starts_with("system reboot")
                })
                .collect::<Vec<_>>();
            assert_eq!(timers.len(), 2, "{tool}: {timers:?}");
            assert!(
                timers.iter().any(|line| line.starts_with("no ")),
                "disarm: {timers:?}"
            );
            lab.stop().await?;
        }
        Ok(())
    }
}
