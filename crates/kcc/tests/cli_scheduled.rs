//! Process-level tests of `kcc scheduled`, the headless scheduled actions.
//!
//! Every test runs the built binary against a fake router; nothing is saved on it.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process and own temporary resources"
)]

#[path = "support/master_key.rs"]
mod master_key;
#[path = "cli_scheduled/round_trip.rs"]
mod round_trip;
#[path = "cli_scheduled/run_now.rs"]
mod run_now;
#[path = "support/spawning.rs"]
mod spawning;
#[path = "cli/support.rs"]
mod support;

use core::error::Error;
use std::fs;

use kcc_app::{persist::StateStore, schedules::ledger::RunLedger};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, Handle};
use serde_json::Value;

use self::support::{Env, Run, TestResult, router};

/// The router every schedule runs on.
const ROUTER: &str = "home";

/// A client the tests register on the router.
const PHONE: &str = "02:00:00:00:16:01";

/// A client the fixture lists as not registered.
const VISITOR: &str = "02:00:00:00:10:02";

/// A policy the fake router has.
const POLICY: &str = "Policy0";

/// The default zone the configuration sets.
const DEFAULT_ZONE: &str = "Europe/Kyiv";

/// A fake router `home` and a configuration with `[cli] role = role`.
async fn fixture(role: &str) -> Result<(Env, Handle), Box<dyn Error>> {
    let (address, handle) = FakeRouter::spawn().await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&format!(
        "[cli]\nrole = {role:?}\n\n[schedules]\ndefault_timezone = {DEFAULT_ZONE:?}\n\n{}",
        router(ROUTER, address, &password)
    ))?;
    Ok((env, handle))
}

/// Runs `kcc <args>` and requires exit `code`.
fn expect(env: &Env, code: i32, args: &[&str]) -> Result<Run, Box<dyn Error>> {
    let run = env.kcc(args)?;
    assert_eq!(run.code, code, "{args:?}: {run:?}");
    Ok(run)
}

/// Runs `kcc --json <args>`, requires exit 0 and parses the document.
fn json_ok(env: &Env, args: &[&str]) -> Result<Value, Box<dyn Error>> {
    let mut all = vec!["--json"];
    all.extend_from_slice(args);
    Ok(serde_json::from_str(&expect(env, 0, &all)?.stdout)?)
}

/// The `kind` of the `--json` failure on stderr.
fn failure_kind(run: &Run) -> Result<String, Box<dyn Error>> {
    let document: Value = serde_json::from_str(run.stderr.trim())?;
    Ok(document
        .pointer("/error/kind")
        .and_then(Value::as_str)
        .ok_or("no error kind")?
        .to_owned())
}

/// The id of the schedule document `document`.
fn id_of(document: &Value) -> Result<String, Box<dyn Error>> {
    Ok(document
        .get("id")
        .and_then(Value::as_str)
        .ok_or("no id")?
        .to_owned())
}

/// The ids `kcc scheduled list` shows.
fn listed(env: &Env) -> Result<Vec<String>, Box<dyn Error>> {
    let list = json_ok(env, &["scheduled", "list"])?;
    list.get("schedules")
        .and_then(Value::as_array)
        .ok_or("no schedules")?
        .iter()
        .map(id_of)
        .collect()
}

/// The audit entries of `kcc scheduled` commands and runs, in order.
fn audited(env: &Env) -> Result<Vec<Value>, Box<dyn Error>> {
    let text = fs::read_to_string(env.state_dir().join("audit.jsonl")).unwrap_or_default();
    let mut entries = Vec::new();
    for line in text.lines() {
        let entry: Value = serde_json::from_str(line)?;
        let action = entry.get("action").and_then(Value::as_str);
        if action.is_some_and(|name| name.starts_with("cli.schedule_") || name == "schedule.run") {
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// The run history of schedule `id`.
fn runs(env: &Env, id: &str) -> Result<Vec<Value>, Box<dyn Error>> {
    let ledger = RunLedger::new(StateStore::open(&env.state_dir())?);
    Ok(ledger
        .runs(id)?
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()?)
}

/// Every parser line the router received.
fn commands(handle: &Handle) -> Vec<String> {
    handle
        .request_log()
        .iter()
        .flat_map(|record| {
            record
                .commands()
                .flatten()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Registers [`PHONE`] on the router.
fn register_phone(env: &Env) -> TestResult {
    drop(expect(
        env,
        0,
        &[
            "--router", ROUTER, "clients", "register", "--mac", PHONE, "--name", "phone",
        ],
    )?);
    Ok(())
}

/// Todo 16: an empty `--days`, `--at 24:00` and an unknown zone are usage errors and
/// store nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_times_are_refused() -> TestResult {
    let (env, handle) = fixture("admin").await?;
    let base = [
        "--json",
        "--router",
        ROUTER,
        "scheduled",
        "add",
        "--name",
        "x",
        "--backup",
    ];
    let cases: [&[&str]; 3] = [
        &["--days", "", "--at", "03:00"],
        &["--days", "mon", "--at", "24:00"],
        &["--days", "mon", "--at", "03:00", "--tz", "Mars/Base"],
    ];
    for case in cases {
        let mut args = base.to_vec();
        args.extend_from_slice(case);

        let refused = expect(&env, 2, &args)?;

        assert_eq!(failure_kind(&refused)?, "usage", "{case:?}");
    }
    assert_eq!(listed(&env)?, Vec::<String>::new());
    handle.shutdown().await?;
    Ok(())
}

/// Todo 16: a policy switch of an unregistered client is refused before any write and
/// stores nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unregistered_client_is_refused_before_any_write() -> TestResult {
    let (env, handle) = fixture("admin").await?;

    let refused = expect(
        &env,
        4,
        &[
            "--json",
            "--router",
            ROUTER,
            "--yes",
            "scheduled",
            "add",
            "--name",
            "Visitor",
            "--days",
            "fri",
            "--at",
            "22:00",
            "--policy-switch",
            "--mac",
            VISITOR,
            "--policy",
            POLICY,
        ],
    )?;

    assert_eq!(failure_kind(&refused)?, "validation");
    assert_eq!(commands(&handle), Vec::<String>::new(), "no write");
    assert_eq!(listed(&env)?, Vec::<String>::new());
    handle.shutdown().await?;
    Ok(())
}

/// Todo 16: a role without `ManageSchedules` is refused by every command.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_operator_is_refused() -> TestResult {
    let (env, handle) = fixture("operator").await?;
    let commands: [&[&str]; 2] = [
        &["--json", "scheduled", "list"],
        &[
            "--json",
            "--router",
            ROUTER,
            "scheduled",
            "add",
            "--name",
            "x",
            "--days",
            "mon",
            "--at",
            "03:00",
            "--backup",
        ],
    ];
    for args in commands {
        let refused = expect(&env, 10, args)?;

        assert_eq!(failure_kind(&refused)?, "policy", "{args:?}");
    }
    assert_eq!(handle.request_count(), 0);
    handle.shutdown().await?;
    Ok(())
}
