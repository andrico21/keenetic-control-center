//! Failed management work retains its recovery receipt.

#[path = "bracket_batch.rs"]
mod batch;
#[path = "bracket_management_fate.rs"]
mod management_fate;

use std::io::{self, Write as _};

use kcc_app::audit::read_entries;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
use serde_json::json;

use super::support::{Env, TestResult, router};

/// Drives the CLI bracket in both recovery modes and checks the failed receipt.
// NOT cancel-safe: a fixture command may apply before cancellation.
async fn check(faults: FaultInjection, line: &str, key: MessageKey) -> TestResult {
    for mode in ["router", "extender"] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let fake = FakeRouter::builder(Profile::default())
            .faults(faults.clone())
            .build()?
            .with_migration(scenario);
        let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
        let env = Env::new("")?;
        let password = env.write(
            "router.password",
            &['a', 'd', 'm', 'i', 'n'].iter().collect::<String>(),
        )?;
        env.write_config(&router("lab-1", address, &password))?;
        let run = if line == "ip http port 8430" {
            env.kcc(&["--yes", "services", "port", "http", "8430"])?
        } else {
            env.kcc(&[
                "--yes",
                "--confirm-destructive",
                "lab-1",
                "router-users",
                "delete",
                "unused",
            ])?
        };
        let armed = key != keys::CLI_ERROR_ROUTER;
        assert_eq!(
            handle.recovery_armed(),
            armed,
            "{mode}: fake recovery state"
        );
        assert_eq!(run.code, 6_i32, "{mode}: {run:?}");
        assert!(
            run.stderr.contains(&tr(Locale::En, key, None)),
            "{mode} {key:?}: {run:?}"
        );
        for absent in [
            keys::MANAGEMENT_DISARM_FAILED,
            keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
        ] {
            if absent != key {
                assert!(
                    !run.stderr.contains(&tr(Locale::En, absent, None)),
                    "{mode}: {run:?}"
                );
            }
        }
        let entries = read_entries(&env.state_dir())?;
        let failed = entries
            .iter()
            .find(|entry| entry.action == "cli.change")
            .ok_or("missing failed change audit")?;
        assert_eq!(
            failed.outcome, "failed",
            "incomplete brackets are failed attempts"
        );
        assert_eq!(
            failed.params_redacted.get("fail_safe_armed"),
            armed.then_some(&json!(true)),
            "{mode}: {failed:?}"
        );
        writeln!(
            io::stderr(),
            "RECOVERY CLI {mode} {line}: key={} exit=6 audit={armed} fake={armed}",
            key.id()
        )?;
        handle.shutdown().await?;
    }
    Ok(())
}

/// A lost management response leaves application unknown and recovery armed.
// NOT cancel-safe: the fixture owns router tasks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_change_reports_armed() -> TestResult {
    check(
        FaultInjection::default().disconnect_after_parse("ip http port".to_owned()),
        "ip http port 8430",
        keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
    )
    .await
}

/// A known applied change reports a refused disarm.
// NOT cancel-safe: the fixture owns router tasks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn applied_change_reports_armed() -> TestResult {
    check(
        FaultInjection::default().fail_parse_matching("no system", 1),
        "ip http port 8430",
        keys::MANAGEMENT_DISARM_FAILED,
    )
    .await
}

/// Refusing both work and cleanup must not hide recovery.
// NOT cancel-safe: the fixture owns router tasks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_change_and_disarm_reports_armed() -> TestResult {
    check(
        FaultInjection::default().fail_parse_matching("no ", 2),
        "no user unused",
        keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
    )
    .await
}

/// Successful cleanup preserves the original work error without an armed note.
// NOT cancel-safe: the fixture owns router tasks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_change_disarmed_preserves_error() -> TestResult {
    check(
        FaultInjection::default().fail_parse_matching("no ", 1),
        "no user unused",
        keys::CLI_ERROR_ROUTER,
    )
    .await
}

/// Curated interface changes retain their native recovery receipt after cleanup fails.
// NOT cancel-safe: the fixture owns router tasks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
            let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
            let env = Env::new("")?;
            let password = env.write(
                "router.password",
                &['a', 'd', 'm', 'i', 'n'].iter().collect::<String>(),
            )?;
            env.write_config(&router("lab-1", address, &password))?;
            let run = env.kcc(&[
                "--yes",
                "interfaces",
                "security-level",
                "Bridge0",
                "private",
            ])?;
            assert!(handle.recovery_armed(), "{mode}: timer remains armed");
            assert_eq!(run.code, 6_i32, "{run:?}");
            assert!(
                run.stderr
                    .contains(&tr(Locale::En, keys::MANAGEMENT_DISARM_FAILED, None)),
                "{mode}: {run:?}"
            );
            assert!(
                handle
                    .request_log()
                    .iter()
                    .any(|record| record.command()
                        == Some("no system configuration fail-safe timer")),
                "guard retains native timer mode"
            );
            let entries = read_entries(&env.state_dir())?;
            let failed = entries
                .iter()
                .find(|entry| entry.action == "cli.change")
                .ok_or("missing failed change audit")?;
            assert_eq!(
                failed.params_redacted.get("fail_safe_armed"),
                Some(&json!(true))
            );
            writeln!(
                io::stderr(),
                "RECOVERY CLI interface {mode}: key=management-disarm-failed exit=6 audit=true fake=true"
            )?;
            handle.shutdown().await?;
        }
    }
    Ok(())
}
