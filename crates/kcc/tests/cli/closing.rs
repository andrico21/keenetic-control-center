//! Closing-step failure matrix through the shipped CLI.
extern crate alloc;

use alloc::sync::Arc;
use core::error::Error;

use kcc_app::{
    audit::read_entries, jobs::JobRunner, persist::StateStore, registry::RouterRegistry,
    settings::OutboundConfig,
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FakeRouter, FaultInjection, Handle, migration, model::Profile};
use serde_json::json;

use super::support::{Env, TestResult, router};

/// Builds an isolated target with a closing fault.
// NOT cancel-safe: starts the fake router and writes fixture files.
pub(super) async fn target(
    mode: &str,
    faults: FaultInjection,
) -> Result<(Env, Handle), Box<dyn Error>> {
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some(mode.to_owned());
    let (address, handle) = FakeRouter::builder(Profile::default())
        .faults(faults)
        .build()?
        .with_migration(scenario)
        .serve(([127, 0, 0, 1], 0).into())
        .await?;
    let env = Env::new("")?;
    let password: String = ['a', 'd', 'm', 'i', 'n'].into_iter().collect();
    let file = env.write("router.password", &password)?;
    env.write_config(&router("target", address, &file))?;
    Ok((env, handle))
}

/// Creates the persisted run identity accepted by resumed preset finish.
// NOT cancel-safe: writes a job record.
pub(super) async fn run_id(env: &Env) -> Result<String, Box<dyn Error>> {
    let state = StateStore::open(&env.state_dir())?;
    let registry = Arc::new(RouterRegistry::new(
        state.clone(),
        &[],
        &OutboundConfig::default(),
    )?);
    let runner = JobRunner::open(state, registry).await?;
    Ok(runner
        .start(
            "migration".to_owned(),
            Some("target".to_owned()),
            false,
            async |_context| Ok(()),
        )
        .await?)
}

/// Every resumed finish reports an armed timer when commit or save is unconfirmed.
// NOT cancel-safe: arms and changes each fixture router.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumed_closing_failures_report_armed() -> TestResult {
    let mut failures = Vec::new();
    for mode in ["router", "extender"] {
        for lost in [false, true] {
            for path in ["preset", "migrate", "config"] {
                let command = if mode == "router" {
                    "fail-safe commit"
                } else {
                    "system configuration save"
                };
                let faults = if lost {
                    FaultInjection::default().disconnect_after_parse(command.to_owned())
                } else {
                    FaultInjection::default().fail_parse_matching(command, 1)
                };
                let (env, handle) = target(mode, faults).await?;
                let arm = env.kcc(&[
                    "--confirm-destructive",
                    "target",
                    "config",
                    "failsafe",
                    "arm",
                ])?;
                assert_eq!(arm.code, 0_i32, "{arm:?}");
                let changed = env.kcc(&["system", "set-description", "closing-pending"])?;
                assert_eq!(changed.code, 0_i32, "{changed:?}");
                let job = run_id(&env).await?;

                let run = match path {
                    "preset" => env.kcc(&["--yes", "preset", "finish", &job, "save"]),
                    "migrate" => env.kcc(&["migrate", "finish", "commit"]),
                    _ => env.kcc(&["config", "failsafe", "commit"]),
                }?;

                let entries = read_entries(&env.state_dir())?;
                let failed = entries
                    .iter()
                    .find(|entry| entry.action == "cli.change" && entry.outcome == "failed")
                    .ok_or("missing failed finish audit")?;
                let armed = !(mode == "router" && lost);
                if run.code != 6_i32
                    || !run.stderr.contains(&tr(
                        Locale::En,
                        keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
                        None,
                    ))
                    || failed.params_redacted.get("fail_safe_armed") != Some(&json!(true))
                    || handle.recovery_armed() != armed
                {
                    failures.push(format!(
                        "{path} {mode} lost={lost}: {run:?}; audit={failed:?}; armed={}",
                        handle.recovery_armed()
                    ));
                }
                handle.shutdown().await?;
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

/// One-shot migration reports a saved configuration and armed timer after refused disarm.
// NOT cancel-safe: applies and saves before requesting disarm.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_shot_saved_disarm_failure_reports_armed() -> TestResult {
    let (env, handle) = target(
        "extender",
        FaultInjection::default().fail_parse_matching("no system reboot", 1),
    )
    .await?;
    let source = env.write("source.txt", "! $$$ Model: Keenetic Giga\n! $$$ Version: 5.1.0\ninterface Bridge11\n description migrated-finish\n!\n")?;
    let from = format!("file:{}", source.display());
    let plan = env.path("plan.json");
    let path = plan.to_str().ok_or("non-UTF-8 path")?;
    let planned = env.kcc(&["migrate", "plan", "--from", &from, "--out", path])?;
    assert_eq!(planned.code, 0_i32, "{planned:?}");

    let run = env.kcc(&[
        "migrate", "apply", "--from", &from, "--plan", path, "--finish", "commit",
    ])?;

    assert_eq!(run.code, 6_i32, "{run:?}");
    assert!(
        run.stderr
            .contains(&tr(Locale::En, keys::FINISH_SAVED_ARMED, None)),
        "{run:?}"
    );
    assert!(handle.recovery_armed());
    assert!(handle.startup_config_text().contains("migrated-finish"));
    let entries = read_entries(&env.state_dir())?;
    let failed = entries
        .iter()
        .find(|entry| entry.action == "cli.change" && entry.outcome == "failed")
        .ok_or("missing one-shot failure audit")?;
    assert_eq!(
        failed.params_redacted,
        json!({"error":"router", "fail_safe_armed":true})
    );
    handle.shutdown().await?;
    Ok(())
}

/// Scheduled rollback describes the saved configuration even after a save succeeded.
// NOT cancel-safe: saves then reboots the fixture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scheduled_rollback_reports_saved_configuration() -> TestResult {
    let (env, handle) = target("extender", FaultInjection::default()).await?;
    let changed = env.kcc(&["system", "set-description", "already-saved"])?;
    assert_eq!(changed.code, 0_i32, "{changed:?}");
    let saved = env.kcc(&["config", "save"])?;
    assert_eq!(saved.code, 0_i32, "{saved:?}");

    let run = env.kcc(&[
        "--confirm-destructive",
        "target",
        "migrate",
        "finish",
        "rollback",
    ])?;

    assert_eq!(run.code, 0_i32, "{run:?}");
    assert!(
        run.stdout
            .contains(&tr(Locale::En, keys::MIGRATE_ROLLBACK_SAVED, None)),
        "{run:?}"
    );
    assert!(handle.running_config_text().contains("already-saved"));
    handle.shutdown().await?;
    Ok(())
}
