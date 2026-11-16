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
pub(crate) async fn target(firmware: Firmware) -> Result<(Env, Handle), Box<dyn Error>> {
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
    let refused = env.kcc(&[
        "migrate", "apply", "--from", &source, "--plan", plan_arg, "--yes",
    ])?;
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
        "--yes",
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
async fn apply_without_confirmation_exits_10_and_writes_nothing() -> TestResult {
    let (env, handle) = target(Firmware::V5_1).await?;
    let source = format!("file:{}", env.path("source.txt").display());
    let plan_path = env.path("plan.json");
    let plan_arg = plan_path.to_str().ok_or("non-UTF-8 path")?;
    let planned = env.kcc(&["migrate", "plan", "--from", &source, "--out", plan_arg])?;
    assert_eq!(planned.code, 0_i32, "{planned:?}");

    let requests_before = handle.request_log().len();
    let refused = env.kcc(&["migrate", "apply", "--from", &source, "--plan", plan_arg])?;

    assert_eq!(
        refused.code, 10_i32,
        "unconfirmed apply exits 10: {refused:?}"
    );
    let log_snapshot = handle.request_log().clone();
    let new_requests = log_snapshot
        .iter()
        .skip(requests_before)
        .collect::<Vec<_>>();
    let parser_commands = new_requests
        .iter()
        .filter_map(|record| record.command().map(str::to_owned))
        .collect::<Vec<_>>();
    assert!(
        parser_commands.is_empty(),
        "no parser commands should be executed when confirmation is missing, but found: {parser_commands:?}"
    );
    let arm_or_reboot_commands = new_requests
        .iter()
        .filter_map(|record| record.command())
        .filter(|cmd| {
            cmd.contains("system configuration fail-safe timer") || cmd.contains("system reboot")
        })
        .collect::<Vec<_>>();
    assert!(
        arm_or_reboot_commands.is_empty(),
        "no arm or reboot commands should be executed when confirmation is missing, but found: {arm_or_reboot_commands:?}"
    );
    let entries = read_entries(&env.state_dir())?;
    let refusals = entries
        .iter()
        .filter(|entry| entry.action == "cli.refused" && entry.outcome == "refused")
        .collect::<Vec<_>>();
    let [refused_entry] = refusals.as_slice() else {
        return Err(format!("one refused entry with outcome=refused expected: {entries:?}").into());
    };
    assert_eq!(refused_entry.router.as_deref(), Some("target"));
    assert_eq!(
        refused_entry.params_redacted.get("reason"),
        Some(&Value::String("confirm_required".to_owned()))
    );
    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_with_yes_flag_applies_without_asking() -> TestResult {
    let (env, handle) = target(Firmware::V5_1).await?;
    let source = format!("file:{}", env.path("source.txt").display());
    let plan_path = env.path("plan.json");
    let plan_arg = plan_path.to_str().ok_or("non-UTF-8 path")?;
    let planned = env.kcc(&["migrate", "plan", "--from", &source, "--out", plan_arg])?;
    assert_eq!(planned.code, 0_i32, "{planned:?}");

    let applied = env.kcc(&[
        "migrate", "apply", "--from", &source, "--plan", plan_arg, "--yes", "--finish", "commit",
    ])?;

    assert_eq!(
        applied.code, 0_i32,
        "apply with --yes succeeds: {applied:?}"
    );
    assert!(
        handle.running_config_text().contains("migrated-1"),
        "the line was applied"
    );
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

    let applied = env.kcc(&[
        "migrate", "apply", "--from", &source, "--plan", plan_arg, "--yes",
    ])?;

    assert_eq!(
        applied.code, 6_i32,
        "verification keeps the router exit code"
    );
    assert!(
        applied
            .stdout
            .contains(&tr(Locale::En, keys::MIGRATE_APPLY_RESTORED, None)),
        "{}",
        applied.stdout
    );
    for stale in [keys::MIGRATE_APPLY_FAILED, keys::CLI_ERROR_ROUTER] {
        let message = tr(Locale::En, stale, None);
        assert!(
            !applied.stderr.contains(&message),
            "completed rollback must not print stale failure text: {}",
            applied.stderr
        );
    }
    assert!(
        handle
            .request_log()
            .iter()
            .any(|request| request.command() == Some("system configuration fail-safe rollback")),
        "native rollback reached the router"
    );
    handle.shutdown().await?;
    Ok(())
}

/// Finishing a kept migration says what the router did, in English and Kazakh.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finishing_a_kept_migration_says_what_the_router_did() -> TestResult {
    for (step, headline, locale, lang) in [
        ("commit", keys::CLI_MIGRATE_COMMITTED, Locale::En, "en"),
        ("rollback", keys::CLI_MIGRATE_ROLLED_BACK, Locale::En, "en"),
        ("commit", keys::CLI_MIGRATE_COMMITTED, Locale::Kk, "kk"),
        ("rollback", keys::CLI_MIGRATE_ROLLED_BACK, Locale::Kk, "kk"),
    ] {
        let (env, handle) = target(Firmware::V5_1).await?;
        let source = format!("file:{}", env.path("source.txt").display());
        let plan_path = env.path("plan.json");
        let plan_arg = plan_path.to_str().ok_or("non-UTF-8 path")?;
        let planned = env.kcc(&["migrate", "plan", "--from", &source, "--out", plan_arg])?;
        assert_eq!(planned.code, 0_i32, "{planned:?}");
        let kept = env.kcc(&[
            "migrate", "apply", "--from", &source, "--plan", plan_arg, "--yes",
        ])?;
        assert_eq!(kept.code, 0_i32, "{kept:?}");
        let finished = env.kcc(&[
            "--lang",
            lang,
            "--confirm-destructive",
            "target",
            "migrate",
            "finish",
            step,
        ])?;
        assert_eq!(finished.code, 0_i32, "{finished:?}");
        assert!(
            finished.stdout.contains(&tr(locale, headline, None)),
            "{step} {lang}: {finished:?}"
        );
        for ordinary in [keys::CLI_APPLIED, keys::CLI_APPLIED_PERSISTED] {
            let text = tr(locale, ordinary, None);
            assert!(
                !finished.stdout.contains(&text) && !finished.stderr.contains(&text),
                "{step} {lang}: {finished:?}"
            );
        }
        let committed = step == "commit";
        assert_eq!(
            handle.startup_config_text().contains("migrated-1"),
            committed,
            "{step}: the saved configuration"
        );
        assert_eq!(
            handle.running_config_text().contains("migrated-1"),
            committed,
            "{step}: the running configuration"
        );
        handle.shutdown().await?;
    }
    Ok(())
}
