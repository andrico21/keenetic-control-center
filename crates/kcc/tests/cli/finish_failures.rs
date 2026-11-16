//! Explicit disarm failures retain the recovery receipt.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::{
    audit::{AuditLog, read_entries},
    jobs::{JobRunner, JobTarget},
    persist::StateStore,
    registry::RouterRegistry,
    settings::OutboundConfig,
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
use serde_json::json;

use super::support::{Env, TestResult, router};

/// Refused and lost disarms report the armed timer after keep or scheduled save.
// NOT cancel-safe: the fixture arms recovery and may save configuration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_disarm_failures_report_armed() -> TestResult {
    for (mode, command) in [
        ("router", "keep-unsaved"),
        ("extender", "keep-unsaved"),
        ("extender", "save"),
        ("extender", "commit"),
    ] {
        for faults in [
            FaultInjection::default().fail_parse_matching("no system", 1),
            FaultInjection::default().disconnect_before_parse("no system".to_owned()),
        ] {
            let mut scenario = migration::Fixture::default();
            scenario.mode = Some(mode.to_owned());
            let (address, handle) = FakeRouter::builder(Profile::default())
                .faults(faults)
                .build()?
                .with_migration(scenario)
                .serve(([127, 0, 0, 1], 0).into())
                .await?;
            let env = Env::new("")?;
            let password = env.write(
                "router.password",
                &['a', 'd', 'm', 'i', 'n'].iter().collect::<String>(),
            )?;
            env.write_config(&router("lab-1", address, &password))?;
            let arm = env.kcc(&[
                "--confirm-destructive",
                "lab-1",
                "config",
                "failsafe",
                "arm",
            ])?;
            assert_eq!(arm.code, 0_i32, "{arm:?}");
            let changed = env.kcc(&["system", "set-description", "finish-pending"])?;
            assert_eq!(changed.code, 0_i32, "{changed:?}");
            let state = StateStore::open(&env.state_dir())?;
            let registry = Arc::new(RouterRegistry::new(
                state.clone(),
                &[],
                &OutboundConfig::default(),
            )?);
            let runner = JobRunner::open(state.clone(), registry, AuditLog::spawn(&state)?).await?;
            let run = runner
                .start(
                    "migration".to_owned(),
                    JobTarget::Read(Some("lab-1".to_owned())),
                    async |_context| Ok(()),
                )
                .await?;

            let finished = if command == "commit" {
                env.kcc(&["config", "failsafe", "commit"])?
            } else {
                env.kcc(&["--yes", "preset", "finish", &run, command])?
            };

            assert_eq!(finished.code, 6_i32, "{mode} {command}: {finished:?}");
            assert!(
                handle.recovery_armed(),
                "failed disarm leaves recovery armed"
            );
            assert_eq!(
                handle.startup_config_text().contains("finish-pending"),
                command != "keep-unsaved"
            );
            assert_eq!(
                finished
                    .stderr
                    .contains(&tr(Locale::En, keys::CLI_SAVED, None)),
                command != "keep-unsaved",
                "{mode} {command}: save receipt"
            );
            assert!(
                finished.stderr.contains(&tr(
                    Locale::En,
                    if command == "save" || command == "commit" {
                        keys::FINISH_SAVED_ARMED
                    } else {
                        keys::MANAGEMENT_DISARM_FAILED
                    },
                    None
                )),
                "{mode} {command}: {finished:?}"
            );
            let entries = read_entries(&env.state_dir())?;
            let failed = entries
                .iter()
                .find(|entry| entry.action == "cli.change" && entry.outcome == "failed")
                .ok_or("missing failed finish audit")?;
            assert_eq!(
                failed.params_redacted.get("fail_safe_armed"),
                Some(&json!(true))
            );
            handle.shutdown().await?;
        }
    }
    Ok(())
}
