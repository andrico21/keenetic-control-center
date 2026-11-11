//! Resumed preset finish authorizes cleanup before saving.

extern crate alloc;

use alloc::sync::Arc;
use std::io::{self, Write as _};

use kcc_app::{
    jobs::JobRunner, persist::StateStore, registry::RouterRegistry, settings::OutboundConfig,
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, FaultInjection, migration, model::Profile};

use super::support::{Env, TestResult, router};

/// A resumed extender run cannot save if the caller cannot disarm its timer.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preset_finish_operator_refuses_before_save_or_discovery() -> TestResult {
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some("extender".to_owned());
    let (address, handle) = FakeRouter::builder(Profile::default())
        .build()?
        .with_migration(scenario)
        .serve(([127, 0, 0, 1], 0).into())
        .await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    let routers = router("lab-1", address, &password);
    env.write_config(&routers)?;
    let arm = env.kcc(&[
        "--confirm-destructive",
        "lab-1",
        "config",
        "failsafe",
        "arm",
    ])?;
    assert_eq!(arm.code, 0_i32, "{arm:?}");
    let changed = env.kcc(&["system", "set-description", "pending-preset"])?;
    assert_eq!(changed.code, 0_i32, "{changed:?}");
    let state = StateStore::open(&env.state_dir())?;
    let registry = Arc::new(RouterRegistry::new(
        state.clone(),
        &[],
        &OutboundConfig::default(),
    )?);
    let runner = JobRunner::open(state, registry).await?;
    let run = runner
        .start(
            "migration".to_owned(),
            Some("lab-1".to_owned()),
            false,
            async |_context| Ok(()),
        )
        .await?;
    env.write_config(&format!("[cli]\nrole = \"operator\"\n{routers}"))?;
    for action in ["save", "keep-unsaved"] {
        let before = handle.request_count();
        let startup = handle.startup_config_text();
        let finish = env.kcc(&["--yes", "preset", "finish", &run, action])?;
        assert_eq!(finish.code, 10_i32, "{finish:?}");
        assert_eq!(
            handle.request_count(),
            before,
            "{action}: refused before any router request"
        );
        assert_eq!(
            handle.startup_config_text(),
            startup,
            "refusal must not save"
        );
        writeln!(
            io::stderr(),
            "REFUSAL CLI operator extender preset finish {action}: zero requests after arm"
        )?;
    }
    handle.shutdown().await?;
    Ok(())
}

/// A saved extender run reports a failed disarm without claiming the save was refused.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preset_finish_disarm_failure_reports_saved_change() -> TestResult {
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some("extender".to_owned());
    let (address, handle) = FakeRouter::builder(Profile::default())
        .faults(FaultInjection::default().fail_parse_matching("no system reboot", 1))
        .build()?
        .with_migration(scenario)
        .serve(([127, 0, 0, 1], 0).into())
        .await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;
    let arm = env.kcc(&[
        "--confirm-destructive",
        "lab-1",
        "config",
        "failsafe",
        "arm",
    ])?;
    assert_eq!(arm.code, 0_i32, "{arm:?}");
    let changed = env.kcc(&["system", "set-description", "saved-preset"])?;
    assert_eq!(changed.code, 0_i32, "{changed:?}");
    let state = StateStore::open(&env.state_dir())?;
    let registry = Arc::new(RouterRegistry::new(
        state.clone(),
        &[],
        &OutboundConfig::default(),
    )?);
    let runner = JobRunner::open(state, registry).await?;
    let run = runner
        .start(
            "migration".to_owned(),
            Some("lab-1".to_owned()),
            false,
            async |_context| Ok(()),
        )
        .await?;
    let finish = env.kcc(&["--yes", "preset", "finish", &run, "save"])?;
    assert_eq!(finish.code, 6_i32, "{finish:?}");
    assert!(
        handle.startup_config_text().contains("saved-preset"),
        "save reached startup"
    );
    assert!(
        finish
            .stderr
            .contains(&tr(Locale::En, keys::MANAGEMENT_DISARM_FAILED, None)),
        "{finish:?}"
    );
    assert!(
        handle
            .request_log()
            .iter()
            .any(|record| record.command() == Some("no system reboot")),
        "cleanup attempted"
    );
    handle.shutdown().await?;
    Ok(())
}
