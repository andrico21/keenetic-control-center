//! Who may open a management bracket over MCP: the change's own permission, behind the
//! server switch.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert wire and request-log contracts"
)]
mod tests {
    use kcc_app::permissions::{Permission, Role};
    use kcc_testkit::{FakeRouter, migration, model::Profile};
    use serde_json::json;

    use crate::lab::{Lab, TestResult};

    /// A raw management line: it moves the router's own web port.
    const LINE: &str = "ip http port 8082";

    /// A fake router reporting `mode`.
    fn router(mode: &str) -> TestResult<FakeRouter> {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        Ok(FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario))
    }

    /// The parser lines the fake received.
    fn commands(lab: &Lab) -> TestResult<Vec<String>> {
        Ok(lab
            .router("lab-1")?
            .request_log()
            .iter()
            .filter_map(|record| record.command().map(str::to_owned))
            .collect())
    }

    /// A role without `Destructive` makes a raw management change in a bracket.
    ///
    /// The change's own permission authorizes arm, change and disarm, once the server switch
    /// and the confirmation allow it.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn change_permission_authorizes_the_bracket() -> TestResult {
        let role = Role::new(
            "raw-writer".to_owned(),
            [Permission::Read, Permission::Write, Permission::RawRci],
            vec!["*".to_owned()],
        );
        for (mode, arm, disarm) in [
            (
                "router",
                "system configuration fail-safe timer reboot 300",
                "no system configuration fail-safe timer",
            ),
            ("extender", "system reboot 300", "no system reboot"),
        ] {
            let off =
                Lab::start_with_destructive(vec![("lab-1", router(mode)?)], role.clone(), false)
                    .await?;
            let disabled = off
                .call(
                    "kcc_cli_parse",
                    json!({"host":"lab-1","line":LINE,"confirm":true}),
                    false,
                )
                .await?;
            assert_eq!(disabled.error(), Some("destructive_disabled"), "{mode}");
            assert_eq!(commands(&off)?, Vec::<String>::new(), "{mode}");
            off.stop().await?;

            let lab = Lab::start(vec![("lab-1", router(mode)?)], role.clone()).await?;
            let unconfirmed = lab
                .call("kcc_cli_parse", json!({"host":"lab-1","line":LINE}), false)
                .await?;
            assert_eq!(unconfirmed.error(), Some("confirm_required"), "{mode}");
            assert_eq!(commands(&lab)?, Vec::<String>::new(), "{mode}");
            let reply = lab
                .call(
                    "kcc_cli_parse",
                    json!({"host":"lab-1","line":LINE,"confirm":true}),
                    false,
                )
                .await?;
            assert_eq!(reply.error(), None, "{mode}: {reply:?}");
            assert_eq!(commands(&lab)?, [arm, LINE, disarm], "{mode}");
            assert!(!lab.router("lab-1")?.recovery_armed(), "{mode}");
            lab.stop().await?;
        }
        Ok(())
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
        let lab = Lab::start(vec![("lab-1", router("router")?)], viewer).await?;
        let before = lab.requests("lab-1")?;
        let reply = lab
            .call(
                "kcc_cli_parse",
                json!({"host":"lab-1","line":LINE,"confirm":true}),
                false,
            )
            .await?;
        assert_eq!(reply.error(), Some("forbidden"), "{reply:?}");
        assert_eq!(lab.requests("lab-1")?, before, "no router request");
        lab.stop().await
    }
}
