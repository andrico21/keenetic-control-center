//! What a migration that stopped after some of its lines says.

use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, FaultInjection, migration, model::Profile};
use serde_json::{Value, json};

use super::support::{Env, TestResult, router};

/// F3 backlog 1: a run that stopped after one applied line, which kcc then rolled back,
/// keeps the router exit code and says how many lines were applied, never that nothing
/// was sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopped_run_says_how_many_lines_were_applied() -> TestResult {
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some("router".to_owned());
    let fake = FakeRouter::builder(Profile::default())
        .faults(FaultInjection::default().fail_parse_matching("migrated-2", 1))
        .build()?
        .with_migration(scenario);
    let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("target", address, &password))?;
    let source = env.write(
        "source.txt",
        "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\ninterface Bridge11\n description migrated-1\n!\ninterface Bridge12\n description migrated-2\n!\n",
    )?;
    let from = format!("file:{}", source.display());
    let plan = env.path("plan.json");
    let path = plan.to_str().ok_or("non-UTF-8 path")?;
    let planned = env.kcc(&["migrate", "plan", "--from", &from, "--out", path])?;
    assert_eq!(planned.code, 0_i32, "{planned:?}");

    let applied = env.kcc(&[
        "--json", "migrate", "apply", "--from", &from, "--plan", path, "--yes",
    ])?;

    assert_eq!(applied.code, 6_i32, "{applied:?}");
    let last = applied.stderr.lines().last().ok_or("no error line")?;
    let document: Value = serde_json::from_str(last)?;
    let error = document.get("error").ok_or("no error object")?;
    assert_eq!(error.get("kind"), Some(&json!("router")), "{document}");
    let mut args = FluentArgs::new();
    args.set("count", "1");
    assert_eq!(
        error.get("details"),
        Some(&json!([tr(
            Locale::En,
            keys::MIGRATE_APPLY_STOPPED_AFTER,
            Some(&args)
        )])),
        "{document}"
    );
    assert!(!handle.running_config_text().contains("migrated-1"));
    handle.shutdown().await?;
    Ok(())
}
