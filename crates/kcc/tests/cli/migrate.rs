//! Migration planning and the documentation-tier acknowledgement.

use core::error::Error;
use std::fs;

use kcc_app::audit::{ActorKind, read_entries};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{
    DEFAULT_PASSWORD, FakeRouter, FaultInjection, Handle, migration,
    model::{Firmware, Model, Profile},
};
use serde_json::Value;

use super::support::{Env, TestResult, USER, router};

/// A saved source configuration that copies one interface description.
const SOURCE: &str = "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\ninterface Bridge11\n description migrated-1\n!\n";

/// A saved source configuration whose Bridge0 description conflicts with the target.
const CONFLICTING_SOURCE: &str = "! $$$ Model: Keenetic Giga\n! $$$ Version: 5.1.0\ninterface Bridge0\n description source-office\n!\n";

/// A migration-ready fake on `firmware` registered as `target`.
async fn target(firmware: Firmware) -> Result<(Env, Handle), Box<dyn Error>> {
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some("router".to_owned());
    let fake = FakeRouter::builder(Profile::new(Model::Kn1811, firmware)?)
        .build()?
        .with_migration(scenario);
    let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("target", address, &password))?;
    drop(env.write("source.txt", SOURCE)?);
    Ok((env, handle))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plan_writes_a_plan_file() -> TestResult {
    let (env, handle) = target(Firmware::V5_1).await?;
    let source = format!("file:{}", env.path("source.txt").display());
    let plan_path = env.path("plan.json");
    let plan_arg = plan_path.to_str().ok_or("non-UTF-8 path")?;
    let run = env.kcc(&["migrate", "plan", "--from", &source, "--out", plan_arg])?;
    assert_eq!(run.code, 0_i32, "{run:?}");
    let plan: Value = serde_json::from_slice(&fs::read(&plan_path)?)?;
    assert!(
        plan.get("plan_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty()),
        "{plan}"
    );
    assert_eq!(
        plan.get("target").and_then(Value::as_str),
        Some("target"),
        "{plan}"
    );
    assert!(
        !fs::read_to_string(&plan_path)?.contains("migrated-1"),
        "plan files are redacted"
    );
    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_plan_names_the_conflicting_catalog_item() -> TestResult {
    let (env, handle) = target(Firmware::V5_1).await?;
    drop(env.write("conflict.txt", CONFLICTING_SOURCE)?);
    let source = format!("file:{}", env.path("conflict.txt").display());
    let plan_path = env.path("plan.json");
    let plan_arg = plan_path.to_str().ok_or("non-UTF-8 path")?;

    let run = env.kcc(&["migrate", "plan", "--from", &source, "--out", plan_arg])?;

    assert_eq!(run.code, 4_i32, "{run:?}");
    assert!(run.stderr.contains("interface description"), "{run:?}");
    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_onto_documentation_tier_needs_the_audited_acknowledgement() -> TestResult {
    let (env, handle) = target(Firmware::V4_3).await?;
    let source = format!("file:{}", env.path("source.txt").display());
    let plan_path = env.path("plan.json");
    let plan_arg = plan_path.to_str().ok_or("non-UTF-8 path")?;
    let planned = env.kcc(&["migrate", "plan", "--from", &source, "--out", plan_arg])?;
    assert_eq!(planned.code, 0_i32, "{planned:?}");
    let refused = env.kcc(&["migrate", "apply", "--from", &source, "--plan", plan_arg])?;
    assert_eq!(refused.code, 10_i32, "{refused:?}");
    assert!(
        refused
            .stderr
            .contains(&tr(Locale::En, keys::MIGRATE_APPLY_TIER, None)),
        "{}",
        refused.stderr
    );
    assert!(
        !handle.running_config_text().contains("migrated-1"),
        "nothing applied"
    );
    let applied = env.kcc(&[
        "migrate",
        "apply",
        "--from",
        &source,
        "--plan",
        plan_arg,
        "--ack-documentation-tier",
        "--finish",
        "commit",
    ])?;
    assert_eq!(applied.code, 0_i32, "{applied:?}");
    assert!(
        handle.running_config_text().contains("migrated-1"),
        "the line was applied"
    );
    let entries = read_entries(&env.state_dir())?;
    let acknowledged = entries
        .iter()
        .find(|entry| entry.action == "migration.ack_documentation_tier")
        .ok_or("the acknowledgement is not audited")?;
    assert_eq!(acknowledged.actor.kind, ActorKind::Cli);
    assert_eq!(acknowledged.actor.id, format!("cli:{USER}"));
    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_verification_reports_the_completed_automatic_rollback() -> TestResult {
    let fake = FakeRouter::builder(Profile::default())
        .faults(FaultInjection::default().silent_noop_path("parse"))
        .build()?;
    let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("target", address, &password))?;
    drop(env.write("source.txt", SOURCE)?);
    let source = format!("file:{}", env.path("source.txt").display());
    let plan_path = env.path("plan.json");
    let plan_arg = plan_path.to_str().ok_or("non-UTF-8 path")?;
    let planned = env.kcc(&["migrate", "plan", "--from", &source, "--out", plan_arg])?;
    assert_eq!(planned.code, 0_i32, "{planned:?}");

    let applied = env.kcc(&["migrate", "apply", "--from", &source, "--plan", plan_arg])?;

    assert_ne!(applied.code, 0_i32, "verification must fail");
    assert!(
        applied
            .stdout
            .contains(&tr(Locale::En, keys::MIGRATE_APPLY_RESTORED, None)),
        "{}",
        applied.stdout
    );
    assert!(
        handle
            .request_log()
            .iter()
            .any(|request| request.command() == Some("system reboot")),
        "rollback reboot reached the router"
    );
    handle.shutdown().await?;
    Ok(())
}
