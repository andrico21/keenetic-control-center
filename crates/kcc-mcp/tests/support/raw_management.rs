//! Raw management permissions and recovery through the MCP transport.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::use_debug,
    reason = "acceptance assertions establish the raw security boundary"
)]
mod tests {
    use std::io::{self, Write as _};

    use kcc_app::permissions::{Permission, Role};
    use kcc_testkit::{FakeRouter, migration, model::Profile};
    use serde_json::{Value, json};

    use crate::lab::{Lab, TestResult, admin};

    /// Headline wire shapes cross independent raw tool handlers.
    fn cases() -> Vec<(&'static str, Value)> {
        vec![
            (
                "kcc_cli_parse",
                json!({"host":"lab-1","line":"no interface Bridge0"}),
            ),
            (
                "kcc_rci_execute",
                json!({"host":"lab-1","catalog_path":"system mode","path":["system","mode"],"value":{"mode":"extender"}}),
            ),
            (
                "kcc_rci_delete",
                json!({"host":"lab-1","catalog_path":"interface","path":["interface"],"value":{"name":"Bridge0"}}),
            ),
            (
                "kcc_rci_batch",
                json!({"host":"lab-1","items":[{"interface":{"name":"Bridge0","no":true}}]}),
            ),
            (
                "kcc_cli_parse",
                json!({"host":"lab-1","line":"interface Bridge0 ip access-group LabAcl in"}),
            ),
            (
                "kcc_cli_parse",
                json!({"host":"lab-1","line":"interface Bridge0 security-level public"}),
            ),
            (
                "kcc_cli_parse",
                json!({"host":"lab-1","line":"ip ssh port 2222"}),
            ),
            (
                "kcc_cli_parse",
                json!({"host":"lab-1","line":"no service http"}),
            ),
            (
                "kcc_rci_batch",
                json!({"host":"lab-1","items":[{"service":{"http":{}}}]}),
            ),
            (
                "kcc_rci_batch",
                json!({"host":"lab-1","items":[{"service telnet":{"no":true}}]}),
            ),
            (
                "kcc_rci_execute",
                json!({"host":"lab-1","catalog_path":"ip telnet port","path":["ip","telnet","port"],"value":{"number":2323_u16}}),
            ),
        ]
    }

    /// Ordinary named-interface leaves stay available to raw writers without recovery.
    // NOT cancel-safe: fixture lifecycle owns router and MCP tasks.
    #[tokio::test]
    async fn ordinary_interface_leaves_apply_without_destructive() -> TestResult {
        for mode in ["router", "extender"] {
            let role = Role::new(
                "raw-writer".to_owned(),
                [Permission::Read, Permission::Write, Permission::RawRci],
                vec!["*".to_owned()],
            );
            let mut scenario = migration::Fixture::default();
            scenario.mode = Some(mode.to_owned());
            for input in [
                json!({"host":"lab-1","items":[{"interface":{"name":"GigabitEthernet0/0","description":{"description":"lab"}}}]}),
                json!({"host":"lab-1","items":[{"interface":{"name":"WifiMaster0/AccessPoint1","ssid":{"ssid":"lab"}}}]}),
            ] {
                let lab = Lab::start(
                    vec![(
                        "lab-1",
                        FakeRouter::builder(Profile::default())
                            .build()?
                            .with_migration(scenario.clone()),
                    )],
                    role.clone(),
                )
                .await?;
                let before = lab.requests("lab-1")?;
                let reply = lab.call("kcc_rci_batch", input.clone(), false).await?;
                assert_eq!(reply.error(), None, "{mode} {input}: {reply:?}");
                assert!(lab.requests("lab-1")? > before, "{mode} {input}");
                assert!(!lab.router("lab-1")?.recovery_armed());
                lab.stop().await?;
            }
        }
        Ok(())
    }

    /// Missing recovery permission and missing confirmation both send zero requests.
    // NOT cancel-safe: fixture lifecycle owns router and MCP tasks.
    #[tokio::test]
    async fn raw_management_gates_both_modes() -> TestResult {
        for mode in ["router", "extender"] {
            for destructive in [false, true] {
                let role = if destructive {
                    admin()
                } else {
                    Role::new(
                        "raw-writer".to_owned(),
                        [Permission::Read, Permission::Write, Permission::RawRci],
                        vec!["*".to_owned()],
                    )
                };
                let mut scenario = migration::Fixture::default();
                scenario.mode = Some(mode.to_owned());
                let mut inputs = cases();
                inputs.push((
                    "kcc_cli_parse",
                    json!({"host":"lab-1","line":"system mode EXTENDER"}),
                ));
                inputs.push((
                    "kcc_cli_parse",
                    json!({"host":"lab-1","line":"interface WifiMaster0/AccessPoint0 schedule sample"}),
                ));
                inputs.push((
                    "kcc_rci_batch",
                    json!({"host":"lab-1","items":[{"interface":{"name":"WifiMaster0/AccessPoint0","schedule":{"schedule":"sample"}}}]}),
                ));
                inputs.push(("kcc_cli_parse", json!({"host":"lab-1","line":"system configuration fail-safe timer reboot 300"})));
                for (tool, mut input) in inputs {
                    let lab = Lab::start(
                        vec![(
                            "lab-1",
                            FakeRouter::builder(Profile::default())
                                .build()?
                                .with_migration(scenario.clone()),
                        )],
                        role.clone(),
                    )
                    .await?;
                    let before = lab.requests("lab-1")?;
                    if !destructive {
                        drop(
                            input
                                .as_object_mut()
                                .ok_or("input object")?
                                .insert("confirm".to_owned(), json!(true)),
                        );
                    }
                    let reply = lab.call(tool, input.clone(), false).await?;
                    assert_eq!(
                        reply.error(),
                        Some(if destructive {
                            "confirm_required"
                        } else {
                            "forbidden"
                        }),
                        "{tool}: {reply:?}"
                    );
                    assert_eq!(lab.requests("lab-1")?, before, "no router traffic");
                    writeln!(
                        io::stderr(),
                        "RAW MCP {mode} destructive={destructive} {tool} {input}: {:?}, zero requests",
                        reply.error()
                    )?;
                    lab.stop().await?;
                }
            }
        }
        Ok(())
    }

    /// Confirmed raw changes arm before work and disarm afterwards in the router's mode.
    // NOT cancel-safe: fixture lifecycle owns router and MCP tasks.
    #[tokio::test]
    async fn raw_management_brackets_both_modes() -> TestResult {
        for mode in ["router", "extender"] {
            let mut scenario = migration::Fixture::default();
            scenario.mode = Some(mode.to_owned());
            for (tool, mut input) in cases() {
                let lab = Lab::start(
                    vec![(
                        "lab-1",
                        FakeRouter::builder(Profile::default())
                            .build()?
                            .with_migration(scenario.clone()),
                    )],
                    admin(),
                )
                .await?;
                drop(
                    input
                        .as_object_mut()
                        .ok_or("input object")?
                        .insert("confirm".to_owned(), json!(true)),
                );
                let before = lab.router("lab-1")?.request_log().len();
                let reply = lab.call(tool, input.clone(), false).await?;
                assert_eq!(reply.error(), None, "{tool}: {reply:?}");
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
                    "{input}: {commands:?}"
                );
                assert_eq!(
                    commands.last().map(String::as_str),
                    Some(disarm),
                    "{input}: {commands:?}"
                );
                assert!(!lab.router("lab-1")?.recovery_armed(), "successful cleanup");
                writeln!(
                    io::stderr(),
                    "RAW MCP admin {mode} {tool} {input}: {commands:?}"
                )?;
                lab.stop().await?;
            }
        }
        Ok(())
    }
}
