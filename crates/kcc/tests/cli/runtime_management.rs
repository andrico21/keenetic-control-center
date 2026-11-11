//! Runtime management operations require recovery authority and confirmation on the CLI.

use std::io::{self, Write as _};

use kcc_app::{
    permissions::{Permission, Role, RolesDocument},
    persist::StateStore,
};
use kcc_rci::{OutboundPolicy, RciClient, RciClientOptions, auth::Credentials};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, migration, model::Profile};
use secrecy::SecretString;

use super::support::{Env, TestResult, router};

/// Arguments covering service stops and every firewall binding/list family.
fn cases() -> Vec<Vec<&'static str>> {
    vec![
        vec!["services", "set", "http", "off"],
        vec!["services", "set", "ssh", "off"],
        vec!["services", "set", "telnet", "off"],
        vec!["firewall", "bind", "RuntimeAcl", "--interface", "Bridge0"],
        vec![
            "firewall",
            "bind",
            "RuntimeAcl",
            "--interface",
            "Bridge0",
            "--remove",
        ],
        vec![
            "firewall",
            "rule",
            "RuntimeAcl",
            "--action",
            "deny",
            "--protocol",
            "ip",
            "--source",
            "0.0.0.0",
            "--destination",
            "0.0.0.0",
        ],
    ]
}

/// A writer is refused before mutation, after read-only runtime detection if needed.
// NOT cancel-safe: fixture lifecycle owns a router task.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_management_operator_sends_nothing() -> TestResult {
    for mode in ["router", "extender"] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let (address, handle) = FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario)
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let env = Env::new("")?;
        let password = env.write("router.password", DEFAULT_PASSWORD)?;
        let mut roles = RolesDocument::default();
        roles.roles.push(Role::new(
            "writer".to_owned(),
            [Permission::Read, Permission::Write],
            vec!["*".to_owned()],
        ));
        StateStore::open(&env.state_dir())?.write(&roles)?;
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
        for role in ["operator", "writer"] {
            env.write_config(&format!(
                "[cli]\nrole = \"{role}\"\n{}",
                router("lab-1", address, &password)
            ))?;
            for args in cases() {
                let before = handle.request_count();
                let log_before = handle.request_log().len();
                let mut confirmed = vec!["--yes"];
                confirmed.extend_from_slice(&args);
                let run = env.kcc(&confirmed)?;
                assert_eq!(run.code, 10_i32, "{args:?}: {run:?}");
                if args.first() == Some(&"services") {
                    assert_eq!(
                        handle.request_count(),
                        before,
                        "service refusal precedes discovery"
                    );
                }
                assert!(
                    handle
                        .request_log()
                        .iter()
                        .skip(log_before)
                        .all(|record| record.command().is_none()),
                    "no mutation after classification"
                );
                writeln!(
                    io::stderr(),
                    "REFUSAL CLI {role} {mode} {}: zero mutation requests",
                    args.join(" ")
                )?;
            }
        }
        handle.shutdown().await?;
    }
    Ok(())
}

/// Service stops require --yes and execute both timer edges in either mode.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_management_services_confirm_and_bracket() -> TestResult {
    let mut failures = Vec::new();
    for mode in ["router", "extender"] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let (address, handle) = FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario)
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let env = Env::new("")?;
        let password = env.write("router.password", DEFAULT_PASSWORD)?;
        env.write_config(&router("lab-1", address, &password))?;
        let client = RciClient::connect_with(
            format!("http://{address}").parse()?,
            Credentials::new("admin".to_owned(), SecretString::from(DEFAULT_PASSWORD)),
            RciClientOptions::default()
                .with_outbound(OutboundPolicy::default().with_loopback(true)),
        )
        .await?;
        for args in cases() {
            drop(
                client
                    .parse(
                        if args.get(1) == Some(&"bind") && !args.contains(&"--remove") {
                            "no interface Bridge0 ip access-group RuntimeAcl in"
                        } else {
                            "interface Bridge0 ip access-group RuntimeAcl in"
                        },
                    )
                    .await?,
            );
            let refusal = env.kcc(&args)?;
            assert_ne!(refusal.code, 0_i32, "{refusal:?}");
            let before = handle.request_log().len();
            let mut confirmed = vec!["--yes"];
            confirmed.extend_from_slice(&args);
            let run = env.kcc(&confirmed)?;
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
                "{run:?} {commands:?}"
            );
            assert_eq!(
                commands.last().map(String::as_str),
                Some(disarm),
                "{run:?} {commands:?}"
            );
            if run.code != 0_i32 {
                failures.push(format!("{}: {}", args.join(" "), run.stderr));
            }
            writeln!(
                io::stderr(),
                "BRACKET CLI admin {mode} {}: confirmation; arm + disarm",
                args.join(" ")
            )?;
        }
        handle.shutdown().await?;
    }
    assert!(failures.is_empty(), "applies must succeed: {failures:?}");
    Ok(())
}
