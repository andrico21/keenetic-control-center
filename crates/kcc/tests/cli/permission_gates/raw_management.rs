//! Binary raw management gates and mode-aware brackets.
#![expect(
    clippy::use_debug,
    reason = "test evidence records exact argv and timer commands"
)]

use std::io::{self, Write as _};

use kcc_app::permissions::Permission;

use super::{TestResult, add_role, lab, mutation_count};

/// Distinct CLI entry points and positive/negative management changes.
fn cases() -> Vec<Vec<&'static str>> {
    vec![
        vec![
            "rci",
            "delete",
            "interface",
            "--data",
            r#"{"name":"Bridge0"}"#,
        ],
        vec![
            "rci",
            "batch",
            "--data",
            r#"[{"interface":{"name":"Bridge0","no":true}}]"#,
        ],
        vec![
            "rci",
            "post",
            "system",
            "mode",
            "--data",
            r#"{"mode":"extender"}"#,
        ],
        vec![
            "rci",
            "post",
            "--data",
            r#"{"interface":{"name":"Bridge0","ip":{"access-group":{"acl":"LabAcl","direction":"in"}}}}"#,
        ],
        vec![
            "rci",
            "post",
            "--data",
            r#"{"interface":{"name":"Bridge0","security-level":{"level":"public"}}}"#,
        ],
        vec![
            "rci",
            "batch",
            "--data",
            r#"[{"service":{"http":{"no":true}}}]"#,
        ],
        vec![
            "rci",
            "post",
            "ip",
            "telnet",
            "port",
            "--data",
            r#"{"number":2323}"#,
        ],
        vec![
            "rci",
            "post",
            "ip",
            "ssh",
            "port",
            "--data",
            r#"{"number":2222}"#,
        ],
        vec!["rci", "post", "--data", r#"{"service":{"ssh":{}}}"#],
    ]
}

/// Raw writers apply ordinary named-interface leaves without the destructive gate.
// NOT cancel-safe: the fixture owns router tasks and child processes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_interface_leaves_apply_without_destructive() -> TestResult {
    for mode in ["router", "extender"] {
        let (env, handle, _address) = lab(mode, "raw-writer").await?;
        add_role(
            &env,
            "raw-writer",
            &[Permission::Read, Permission::Write, Permission::RawRci],
        )?;
        for input in [
            vec![
                "rci",
                "post",
                "interface",
                "--data",
                r#"{"name":"GigabitEthernet0/0","description":{"description":"lab"}}"#,
            ],
            vec![
                "rci",
                "batch",
                "--data",
                r#"[{"interface":{"name":"WifiMaster0/AccessPoint1","ssid":{"ssid":"lab"}}}]"#,
            ],
        ] {
            let before = handle.request_log().len();
            let mut args = vec!["--yes"];
            args.extend(input);
            let run = env.kcc(&args)?;
            assert_eq!(run.code, 0_i32, "{mode} {args:?}: {run:?}");
            assert!(mutation_count(&handle, before) != 0, "{mode} {args:?}");
            assert!(!handle.recovery_armed());
        }
        handle.shutdown().await?;
    }
    Ok(())
}

/// Raw writers cannot bypass recovery authorization, including timer arming.
// NOT cancel-safe: the fixture owns router tasks and child processes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_management_permission_refuses_both_modes() -> TestResult {
    for mode in ["router", "extender"] {
        let (env, handle, _address) = lab(mode, "raw-writer").await?;
        add_role(
            &env,
            "raw-writer",
            &[Permission::Read, Permission::Write, Permission::RawRci],
        )?;
        let mut inputs = cases();
        inputs.push(vec![
            "rci",
            "post",
            "system",
            "configuration",
            "fail-safe",
            "timer",
            "--data",
            r#"{"action":"reboot","interval":300}"#,
        ]);
        inputs.push(vec![
            "rci",
            "post",
            "--data",
            r#"{"interface":{"name":"WifiMaster0/AccessPoint0","schedule":{"schedule":"sample"}}}"#,
        ]);
        inputs.push(vec![
            "rci",
            "batch",
            "--data",
            r#"[{"interface":{"name":"WifiMaster0/AccessPoint0","schedule":{"schedule":"sample"}}}]"#,
        ]);
        for input in inputs {
            let before = handle.request_log().len();
            let mut args = vec!["--yes", "--confirm-destructive", "lab-1"];
            args.extend(input);
            let run = env.kcc(&args)?;
            assert_eq!(run.code, 10_i32, "{args:?}: {run:?}");
            assert_eq!(mutation_count(&handle, before), 0, "{args:?}");
            writeln!(
                io::stderr(),
                "RAW CLI raw-writer {mode} {args:?}: exit 10, zero mutations"
            )?;
        }
        handle.shutdown().await?;
    }
    Ok(())
}

/// Confirmed administrators receive native or scheduled recovery around every raw shape.
// NOT cancel-safe: the fixture owns router tasks and child processes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_management_brackets_both_modes() -> TestResult {
    for mode in ["router", "extender"] {
        let (env, handle, _address) = lab(mode, "admin").await?;
        for input in cases() {
            let before = handle.request_log().len();
            let mut args = vec!["--yes", "--confirm-destructive", "lab-1"];
            args.extend(input);
            let run = env.kcc(&args)?;
            assert_eq!(run.code, 0_i32, "{args:?}: {run:?}");
            let commands = handle
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
                "{args:?}: {commands:?}"
            );
            assert_eq!(
                commands.last().map(String::as_str),
                Some(disarm),
                "{args:?}: {commands:?}"
            );
            assert!(!handle.recovery_armed(), "successful cleanup");
            writeln!(io::stderr(), "RAW CLI admin {mode} {args:?}: {commands:?}")?;
        }
        handle.shutdown().await?;
    }
    Ok(())
}

/// Curated Wi-Fi and segment management changes need recovery authority before mutation.
// NOT cancel-safe: the fixture owns router tasks and child processes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn curated_wifi_and_segment_permission_refuses_both_modes() -> TestResult {
    for role in ["operator", "writer"] {
        for mode in ["router", "extender"] {
            let (env, handle, _address) = lab(mode, role).await?;
            if role == "writer" {
                add_role(&env, role, &[Permission::Read, Permission::Write])?;
            }
            for input in [
                vec![
                    "--yes",
                    "wifi",
                    "enable",
                    "--ap",
                    "WifiMaster0/AccessPoint0",
                    "off",
                ],
                vec![
                    "--yes",
                    "segments",
                    "create",
                    "7",
                    "--vlan",
                    "7",
                    "--address",
                    "198.51.100.1",
                    "--mask",
                    "255.255.255.0",
                    "--dhcp-begin",
                    "198.51.100.10",
                    "--dhcp-end",
                    "198.51.100.50",
                    "--access-point",
                    "WifiMaster0/AccessPoint0",
                ],
            ] {
                let before = handle.request_log().len();
                let run = env.kcc(&input)?;
                assert_eq!(run.code, 10_i32, "{role} {mode} {input:?}: {run:?}");
                assert!(
                    handle
                        .request_log()
                        .iter()
                        .skip(before)
                        .all(|record| record.command().is_none()),
                    "{input:?}"
                );
            }
            handle.shutdown().await?;
        }
    }
    Ok(())
}
