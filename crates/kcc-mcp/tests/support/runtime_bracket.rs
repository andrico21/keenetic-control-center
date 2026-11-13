//! Runtime management classification at the MCP boundary.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish management recovery"
)]
mod tests {
    use std::io::{self, Write as _};

    use kcc_app::permissions::{Permission, Role};
    use kcc_rci::{OutboundPolicy, RciClient, RciClientOptions, auth::Credentials};
    use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, migration, model::Profile};
    use secrecy::SecretString;
    use serde_json::{Value, json};

    use crate::lab::{Lab, TestResult, admin};

    /// Management-sensitive inputs, including a rule on a previously bound list.
    fn cases() -> Vec<(&'static str, Value)> {
        let mut cases = vec![
            (
                "kcc_firewall_write",
                json!({"host":"lab-1","op":"binding","acl":"RuntimeAcl","interface":"Bridge0"}),
            ),
            (
                "kcc_firewall_write",
                json!({"host":"lab-1","op":"binding","acl":"RuntimeAcl","interface":"Bridge0","remove":true}),
            ),
            (
                "kcc_firewall_write",
                json!({"host":"lab-1","op":"rule","acl":"RuntimeAcl","verdict":"deny","protocol":"ip","source":"0.0.0.0","destination":"0.0.0.0"}),
            ),
        ];
        for name in ["http", "ssh", "telnet"] {
            cases.push((
                "kcc_services_write",
                json!({"host":"lab-1","op":"set_service","name":name,"enabled":false}),
            ));
        }
        cases
    }

    /// Ordinary firewall changes remain available without recovery authority.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn ordinary_firewall_writer_needs_no_recovery_permission() -> TestResult {
        for mode in ["router", "extender"] {
            for permissions in [
                vec![Permission::Read, Permission::Write],
                vec![
                    Permission::Read,
                    Permission::Write,
                    Permission::Save,
                    Permission::Migrate,
                ],
            ] {
                let role = Role::new("writer".to_owned(), permissions, vec!["*".to_owned()]);
                let lab = lab(mode, role).await?;
                for input in [
                    json!({"host":"lab-1","op":"rule","acl":"OrdinaryAcl","protocol":"ip","source":"192.0.2.10","destination":"198.51.100.10"}),
                    json!({"host":"lab-1","op":"binding","acl":"OrdinaryAcl","interface":"ISP"}),
                ] {
                    let before = lab.router("lab-1")?.request_log().len();
                    let reply = lab.call("kcc_firewall_write", input.clone(), false).await?;
                    assert_eq!(reply.error(), None, "{mode} {input}: {reply:?}");
                    let commands = lab
                        .router("lab-1")?
                        .request_log()
                        .iter()
                        .skip(before)
                        .filter_map(|record| record.command().map(str::to_owned))
                        .collect::<Vec<_>>();
                    assert_eq!(
                        commands.len(),
                        1,
                        "ordinary write without timer: {commands:?}"
                    );
                    assert!(
                        !commands.iter().any(|line| line.contains("system")),
                        "no recovery commands"
                    );
                    writeln!(
                        io::stderr(),
                        "ORDINARY MCP writer {mode} {input}: applied without timer"
                    )?;
                }
                lab.stop().await?;
            }
        }
        Ok(())
    }

    /// Runtime discovery never grants a caller without the change's permission mutation
    /// authority, whatever else it holds.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn runtime_management_missing_permission_sends_nothing() -> TestResult {
        for mode in ["router", "extender"] {
            for permissions in [
                vec![Permission::Read],
                vec![
                    Permission::Read,
                    Permission::Save,
                    Permission::Migrate,
                    Permission::Destructive,
                ],
            ] {
                let role = Role::new("non-writer".to_owned(), permissions, vec!["*".to_owned()]);
                let lab = lab(mode, role).await?;
                for (tool, mut input) in cases() {
                    drop(
                        input
                            .as_object_mut()
                            .ok_or("input object")?
                            .insert("confirm".to_owned(), json!(true)),
                    );
                    let before = lab.requests("lab-1")?;
                    let log_before = lab.router("lab-1")?.request_log().len();
                    let reply = lab.call(tool, input.clone(), false).await?;
                    assert_eq!(
                        reply.error(),
                        Some("forbidden"),
                        "{mode} {tool} {input}: {reply:?}"
                    );
                    if tool == "kcc_services_write" {
                        assert_eq!(
                            lab.requests("lab-1")?,
                            before,
                            "service refusal precedes discovery"
                        );
                    }
                    assert!(
                        lab.router("lab-1")?
                            .request_log()
                            .iter()
                            .skip(log_before)
                            .all(|record| record.command().is_none()),
                        "no mutation after classification"
                    );
                    writeln!(
                        io::stderr(),
                        "REFUSAL MCP {mode} {tool} {input}: forbidden, zero mutation requests"
                    )?;
                }
                lab.stop().await?;
            }
        }
        Ok(())
    }

    /// Every runtime-classified operation needs confirmation and has both timer edges.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn runtime_management_confirm_and_bracket() -> TestResult {
        let mut failures = Vec::new();
        for mode in ["router", "extender"] {
            for (tool, mut input) in cases() {
                let lab = lab(mode, admin()).await?;
                let line = if input.get("op").and_then(Value::as_str) == Some("binding")
                    && input.get("remove") != Some(&json!(true))
                {
                    "no interface Bridge0 ip access-group RuntimeAcl in"
                } else {
                    "interface Bridge0 ip access-group RuntimeAcl in"
                };
                let seeded = lab
                    .call(
                        "kcc_cli_parse",
                        json!({"host":"lab-1","line":line,"confirm":true}),
                        false,
                    )
                    .await?;
                assert_eq!(seeded.error(), None, "{seeded:?}");
                let refused = lab.call(tool, input.clone(), false).await?;
                assert_eq!(
                    refused.error(),
                    Some("confirm_required"),
                    "{mode} {input}: {refused:?}"
                );
                drop(
                    input
                        .as_object_mut()
                        .ok_or("input object")?
                        .insert("confirm".to_owned(), json!(true)),
                );
                let before = lab.router("lab-1")?.request_log().len();
                let reply = lab.call(tool, input.clone(), false).await?;
                let commands = lab
                    .router("lab-1")?
                    .request_log()
                    .iter()
                    .skip(before)
                    .filter_map(|record| record.command().map(str::to_owned))
                    .collect::<Vec<_>>();
                let (arm, disarm) = if mode == "router" {
                    (
                        "system configuration fail-safe timer reboot 300",
                        "no system configuration fail-safe timer",
                    )
                } else {
                    ("system reboot 300", "no system reboot")
                };
                assert_eq!(
                    commands.first().map(String::as_str),
                    Some(arm),
                    "{input}: {reply:?}, {commands:?}"
                );
                assert_eq!(
                    commands.last().map(String::as_str),
                    Some(disarm),
                    "{input}: {reply:?}, {commands:?}"
                );
                if let Some(error) = reply.error() {
                    failures.push(format!("{mode} {tool} {input}: {error}"));
                }
                writeln!(
                    io::stderr(),
                    "BRACKET MCP admin {mode} {tool} {input}: confirm_required; arm + disarm"
                )?;
                lab.stop().await?;
            }
        }
        assert!(failures.is_empty(), "applies must succeed: {failures:?}");
        Ok(())
    }

    /// Starts a real MCP session with a mode-specific fake router.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    async fn lab(mode: &str, role: Role) -> TestResult<Lab> {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let fake = FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario);
        let (address, seed_handle) = fake.clone().serve(([127, 0, 0, 1], 0).into()).await?;
        let client = RciClient::connect_with(
            format!("http://{address}").parse()?,
            Credentials::new("admin".to_owned(), SecretString::from(DEFAULT_PASSWORD)),
            RciClientOptions::default()
                .with_outbound(OutboundPolicy::default().with_loopback(true)),
        )
        .await?;
        drop(
            client
                .parse("interface Bridge0 ip access-group RuntimeAcl in")
                .await?,
        );
        seed_handle.shutdown().await?;
        Lab::start(vec![("lab-1", fake)], role).await
    }
}
