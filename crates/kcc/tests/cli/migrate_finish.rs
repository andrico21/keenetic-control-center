//! Resumed migration completion preserves the selected recovery mechanism.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{
    audit::read_entries,
    permissions::{Permission, Role, RolesDocument},
    persist::StateStore,
};
use kcc_testkit::{
    DEFAULT_PASSWORD, FakeRouter, migration,
    model::Profile,
    time::{Clock, MockClock},
};

use super::support::{Env, TestResult, router};

/// Scheduled commit refuses built-in and custom savers before mutation and audits both.
// NOT cancel-safe: fixture services and refusal audit writes may outlive cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn migration_scheduled_commit_audits_missing_recovery_permission() -> TestResult {
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some("extender".to_owned());
    let (address, handle) = FakeRouter::builder(Profile::default())
        .build()?
        .with_migration(scenario)
        .serve(([127, 0, 0, 1], 0).into())
        .await?;
    let env = Env::new("")?;
    let password = env.write(
        "router.password",
        &['a', 'd', 'm', 'i', 'n'].iter().collect::<String>(),
    )?;
    let routers = router("target", address, &password);
    let mut roles = RolesDocument::default();
    roles.roles.push(Role::new(
        "migration-saver".to_owned(),
        [Permission::Read, Permission::Migrate, Permission::Save],
        vec!["target".to_owned()],
    ));
    StateStore::open(&env.state_dir())?.write(&roles)?;
    for role in ["operator", "migration-saver"] {
        env.write_config(&format!("[cli]\nrole = {role:?}\n{routers}"))?;
        let before = handle.request_log().len();

        let run = env.kcc(&["migrate", "finish", "commit"])?;

        assert_eq!(run.code, 10_i32, "{role}: {run:?}");
        assert!(
            handle
                .request_log()
                .iter()
                .skip(before)
                .all(|record| record.command().is_none()),
            "{role}: no mutation before refusal"
        );
    }
    let entries = read_entries(&env.state_dir())?;
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.action == "cli.refused" && entry.outcome == "forbidden")
            .count(),
        2
    );
    handle.shutdown().await?;
    Ok(())
}

/// Scheduled rollback reboots directly while router mode retains native rollback.
// NOT cancel-safe: the fixture arms recovery and rolls back configuration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn migration_rollback_uses_the_selected_mode() -> TestResult {
    for (mode, expected) in [
        ("extender", "system reboot"),
        ("router", "system configuration fail-safe rollback"),
    ] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let (address, handle) = FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario)
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let env = Env::new("")?;
        let password = env.write(
            "router.password",
            &['a', 'd', 'm', 'i', 'n'].iter().collect::<String>(),
        )?;
        env.write_config(&router("target", address, &password))?;
        let arm = env.kcc(&[
            "--confirm-destructive",
            "target",
            "config",
            "failsafe",
            "arm",
        ])?;
        assert_eq!(arm.code, 0_i32, "{arm:?}");
        let changed = env.kcc(&["system", "set-description", "rollback-migration"])?;
        assert_eq!(changed.code, 0_i32, "{changed:?}");
        let before = handle.request_log().len();

        let finished = env.kcc(&[
            "--confirm-destructive",
            "target",
            "migrate",
            "finish",
            "rollback",
        ])?;

        assert_eq!(finished.code, 0_i32, "{mode}: {finished:?}");
        assert!(!handle.running_config_text().contains("rollback-migration"));
        assert!(!handle.recovery_armed(), "rollback resolves recovery");
        assert!(
            handle
                .request_log()
                .iter()
                .skip(before)
                .any(|record| record.command() == Some(expected)),
            "{mode}: expected {expected}"
        );
        handle.shutdown().await?;
    }
    Ok(())
}

/// A kept migration commits in either mode and leaves no timer to discard later work.
// NOT cancel-safe: the fixture applies and saves router configuration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn migration_commit_cancels_the_selected_timer() -> TestResult {
    for mode in ["extender", "router"] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let clock = Arc::new(MockClock::new());
        let concrete = Arc::clone(&clock);
        let router_clock: Arc<dyn Clock> = concrete;
        let (address, handle) = FakeRouter::builder(Profile::default())
            .clock(router_clock)
            .build()?
            .with_migration(scenario)
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let env = Env::new("")?;
        let password = env.write("router.password", DEFAULT_PASSWORD)?;
        env.write_config(&router("target", address, &password))?;
        let source = env.write(
            "source.txt",
            "! $$$ Model: Keenetic Giga\n! $$$ Version: 5.1.0\ninterface Bridge11\n description migrated-finish\n!\n",
        )?;
        let from = format!("file:{}", source.display());
        let plan = env.path("plan.json");
        let path = plan.to_str().ok_or("non-UTF-8 path")?;
        let planned = env.kcc(&["migrate", "plan", "--from", &from, "--out", path])?;
        assert_eq!(planned.code, 0_i32, "{planned:?}");
        let applied = env.kcc(&["migrate", "apply", "--from", &from, "--plan", path])?;
        assert_eq!(applied.code, 0_i32, "{applied:?}");
        let before = handle.request_log().len();

        let finished = env.kcc(&["migrate", "finish", "commit"])?;

        assert_eq!(finished.code, 0_i32, "{mode}: {finished:?}");
        assert!(handle.startup_config_text().contains("migrated-finish"));
        let commands = handle
            .request_log()
            .into_iter()
            .skip(before)
            .filter_map(|record| record.command().map(str::to_owned))
            .collect::<Vec<_>>();
        let expected = if mode == "router" {
            "system configuration fail-safe commit"
        } else {
            "no system reboot"
        };
        assert!(
            commands.iter().any(|command| command == expected),
            "{mode}: {commands:?}"
        );
        if mode == "extender" {
            assert!(
                commands
                    .iter()
                    .any(|command| command == "system configuration save"),
                "scheduled commit must save before disarming: {commands:?}"
            );
        }
        let changed = env.kcc(&["system", "set-description", "after-migration-commit"])?;
        assert_eq!(changed.code, 0_i32, "{changed:?}");
        clock.advance(Duration::from_secs(901));
        let state = env.kcc(&["config", "state"])?;
        assert_eq!(state.code, 0_i32, "{state:?}");
        assert!(
            handle
                .running_config_text()
                .contains("after-migration-commit"),
            "{mode}: a committed migration must not reboot later"
        );
        handle.shutdown().await?;
    }
    Ok(())
}
