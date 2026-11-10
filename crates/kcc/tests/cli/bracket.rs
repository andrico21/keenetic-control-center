//! Management brackets close with the authority that opened them.
use std::io::{self, Write as _};

use kcc_app::{
    permissions::{Permission, Role, RolesDocument},
    persist::StateStore,
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};

use super::support::{Env, TestResult, router};

/// A raw destructive role can complete recovery without ordinary write access.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn management_bracket_without_write_permission() -> TestResult {
    for mode in ["router", "extender"] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let fake = FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario);
        let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
        let env = Env::new("")?;
        let password = env.write(
            "router.password",
            &['a', 'd', 'm', 'i', 'n'].iter().collect::<String>(),
        )?;
        let mut roles = RolesDocument::default();
        roles.roles.push(Role::new(
            "rawdes".to_owned(),
            [
                Permission::Read,
                Permission::RawRci,
                Permission::Destructive,
            ],
            vec!["*".to_owned()],
        ));
        StateStore::open(&env.state_dir())?.write(&roles)?;
        env.write_config(&format!(
            "[cli]\nrole = \"rawdes\"\n{}",
            router("lab-1", address, &password)
        ))?;
        let run = env.kcc(&[
            "--yes",
            "rci",
            "post",
            "ip",
            "http",
            "port",
            "--data",
            r#"{"port":8082}"#,
        ])?;
        let commands = handle
            .request_log()
            .iter()
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
        assert!(
            commands.iter().any(|line| line == arm) && commands.iter().any(|line| line == disarm),
            "CLI rawdes {mode}: {commands:?}; {run:?}"
        );
        assert_eq!(run.code, 0_i32, "{run:?}");
        writeln!(io::stderr(), "BRACKET CLI rawdes {mode}: arm + disarm")?;
        handle.shutdown().await?;
    }
    Ok(())
}

/// A refused disarm reports the already-applied change rather than a refused mutation.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn management_bracket_disarm_failure_reports_applied() -> TestResult {
    let fake = FakeRouter::builder(Profile::default())
        .faults(FaultInjection::default().fail_parse_matching("no system", 1))
        .build()?;
    let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
    let env = Env::new("")?;
    let password = env.write(
        "router.password",
        &['a', 'd', 'm', 'i', 'n'].iter().collect::<String>(),
    )?;
    env.write_config(&router("lab-1", address, &password))?;
    let run = env.kcc(&["--yes", "services", "port", "http", "8082"])?;
    assert!(
        handle.running_config_text().contains("port 8082"),
        "management port applied: {run:?}"
    );
    let message = tr(Locale::En, keys::MANAGEMENT_DISARM_FAILED, None);
    assert!(
        run.stderr.contains(&message) || run.stdout.contains(&message),
        "{run:?}"
    );
    handle.shutdown().await?;
    Ok(())
}
