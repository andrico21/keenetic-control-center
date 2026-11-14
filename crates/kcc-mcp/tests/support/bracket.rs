//! Who may open a management bracket over MCP, behind the server switch, and what a router
//! whose mode is undecidable receives.
#![expect(
    clippy::missing_errors_doc,
    reason = "test fixtures return the boxed error of the step that failed"
)]

#[path = "bracket_dead_audit.rs"]
mod dead_audit;

use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};

use crate::lab::{Lab, TestResult};

/// A fake router reporting `mode` with `faults`.
pub(crate) fn router(mode: &str, faults: FaultInjection) -> TestResult<FakeRouter> {
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some(mode.to_owned());
    Ok(FakeRouter::builder(Profile::default())
        .faults(faults)
        .build()?
        .with_migration(scenario))
}

/// The parser lines `lab-1` received.
pub(crate) fn commands(lab: &Lab) -> TestResult<Vec<String>> {
    Ok(lab
        .router("lab-1")?
        .request_log()
        .iter()
        .filter_map(|record| record.command().map(str::to_owned))
        .collect())
}

/// The arm and disarm lines of the recovery of `mode`.
pub(crate) fn edges(mode: &str) -> [&'static str; 2] {
    if mode == "router" {
        [
            "system configuration fail-safe timer reboot 300",
            "no system configuration fail-safe timer",
        ]
    } else {
        ["system reboot 300", "no system reboot"]
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert wire and request-log contracts"
)]
mod tests {
    use kcc_app::permissions::{Permission, Role};
    use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
    use serde_json::json;

    use super::{commands, edges, router};
    use crate::lab::{Lab, TestResult, admin};

    /// A raw management line: it moves the router's own web port.
    const LINE: &str = "ip http port 8082";

    /// A role without `Destructive` makes a raw management change in a bracket once the
    /// server switch and the confirmation allow it.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn change_permission_authorizes_the_bracket() -> TestResult {
        let role = Role::new(
            "raw-writer".to_owned(),
            [Permission::Read, Permission::Write, Permission::RawRci],
            vec!["*".to_owned()],
        );
        let parse = json!({"host":"lab-1","line":LINE,"confirm":true});
        let switched_off = router("router", FaultInjection::default())?;
        let off =
            Lab::start_with_destructive(vec![("lab-1", switched_off)], role.clone(), false).await?;
        let disabled = off.call("kcc_cli_parse", parse.clone(), false).await?;
        assert_eq!(disabled.error(), Some("destructive_disabled"));
        assert_eq!(commands(&off)?, Vec::<String>::new());
        off.stop().await?;

        let fake = router("router", FaultInjection::default())?;
        let lab = Lab::start(vec![("lab-1", fake)], role).await?;
        let unconfirmed = lab
            .call("kcc_cli_parse", json!({"host":"lab-1","line":LINE}), false)
            .await?;
        assert_eq!(unconfirmed.error(), Some("confirm_required"));
        assert_eq!(commands(&lab)?, Vec::<String>::new());
        let reply = lab.call("kcc_cli_parse", parse, false).await?;
        assert_eq!(reply.error(), None, "{reply:?}");
        let [arm, disarm] = edges("router");
        assert_eq!(commands(&lab)?, [arm, LINE, disarm]);
        assert!(!lab.router("lab-1")?.recovery_armed());
        lab.stop().await
    }

    /// A raw batch needs `RawRci`, not `Write`, for its whole bracket.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn management_bracket_without_write_permission() -> TestResult {
        let role = Role::new(
            "rawdes".to_owned(),
            [
                Permission::Read,
                Permission::RawRci,
                Permission::Destructive,
            ],
            vec!["*".to_owned()],
        );
        let fake = router("router", FaultInjection::default())?;
        let lab = Lab::start(vec![("lab-1", fake)], role).await?;
        let items = json!([{"ip":{"http":{"port":{"port":8082_u16}}}}]);
        let reply = lab
            .call(
                "kcc_rci_batch",
                json!({"host":"lab-1","items":items,"confirm":true}),
                false,
            )
            .await?;
        assert_eq!(reply.error(), None, "{reply:?}");
        let sent = commands(&lab)?;
        assert_eq!(sent.first().map(String::as_str), Some(edges("router")[0]));
        assert_eq!(sent.last().map(String::as_str), Some(edges("router")[1]));
        lab.stop().await
    }

    /// A viewer is refused before kcc sends anything to the router.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn viewer_is_refused_before_any_router_request() -> TestResult {
        let viewer = Role::new(
            "viewer".to_owned(),
            [Permission::Read],
            vec!["*".to_owned()],
        );
        let fake = router("router", FaultInjection::default())?;
        let lab = Lab::start(vec![("lab-1", fake)], viewer).await?;
        let before = lab.requests("lab-1")?;
        let parse = json!({"host":"lab-1","line":LINE,"confirm":true});
        let reply = lab.call("kcc_cli_parse", parse, false).await?;
        assert_eq!(reply.error(), Some("forbidden"), "{reply:?}");
        assert_eq!(lab.requests("lab-1")?, before, "no router request");
        lab.stop().await
    }

    /// A router with neither a known mode nor a fail-safe timer gets `router_mode_unknown`
    /// and nothing else.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn recovery_mechanism_follows_the_reported_mode() -> TestResult {
        for (mode, omit_fail_safe) in [(Some("bridge"), false), (None, true)] {
            let mut scenario = migration::Fixture::default();
            scenario.mode = mode.map(str::to_owned);
            scenario.omit_fail_safe = omit_fail_safe;
            let fake = FakeRouter::builder(Profile::default())
                .build()?
                .with_migration(scenario);
            let lab = Lab::start(vec![("lab-1", fake)], admin()).await?;
            let parse = json!({"host":"lab-1","line":LINE,"confirm":true});
            let reply = lab.call("kcc_cli_parse", parse, false).await?;
            let label = format!("{mode:?} omit={omit_fail_safe}: {reply:?}");
            assert_eq!(reply.error(), Some("router_mode_unknown"), "{label}");
            assert!(commands(&lab)?.is_empty(), "nothing is sent: {label}");
            let config = lab.router("lab-1")?.running_config_text();
            assert!(!config.contains("port 8082"), "{label}");
            lab.stop().await?;
        }
        Ok(())
    }
}
