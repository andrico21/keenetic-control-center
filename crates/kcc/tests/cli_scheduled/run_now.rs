//! `kcc scheduled run-now`: the run in this process, its confirmations and a busy router.

use core::time::Duration;
use std::time::Instant;

use kcc_app::persist::StateStore;
use serde_json::{Value, json};

use crate::{
    PHONE, POLICY, ROUTER, audited, commands, expect, failure_kind, fixture, id_of, json_ok,
    register_phone, runs,
    support::{Env, TestResult, USER},
};

/// How long a busy run would wait before its first retry.
const BUSY_RETRY: Duration = Duration::from_secs(60);

/// Adds a policy switch of [`PHONE`] to [`POLICY`] and answers its id.
fn add_switch(env: &Env) -> TestResult<String> {
    let added = json_ok(
        env,
        &[
            "--router",
            ROUTER,
            "--yes",
            "scheduled",
            "add",
            "--name",
            "Phone at night",
            "--days",
            "mon,tue,wed,thu,fri,sat,sun",
            "--at",
            "22:00",
            "--policy-switch",
            "--mac",
            PHONE,
            "--policy",
            POLICY,
        ],
    )?;
    id_of(&added)
}

/// Todo 16: a run-now of a policy switch changes the running configuration only, is
/// recorded without a slot and audited as requested by the CLI user.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_policy_run_now_changes_only_the_running_configuration() -> TestResult {
    let (env, handle) = fixture("admin").await?;
    register_phone(&env)?;
    let id = add_switch(&env)?;

    let ran = json_ok(&env, &["--yes", "scheduled", "run-now", &id])?;

    assert_eq!(
        (
            ran.get("id"),
            ran.pointer("/result/kind"),
            ran.pointer("/result/unsaved")
        ),
        (
            Some(&json!(id)),
            Some(&json!("succeeded")),
            Some(&json!(true))
        ),
        "{ran}"
    );
    let line = format!("ip hotspot host {PHONE} policy {POLICY}");
    assert!(
        handle.running_config_text().contains(&line),
        "{}",
        handle.running_config_text()
    );
    assert!(!handle.startup_config_text().contains(&line), "never saved");
    let history = runs(&env, &id)?;
    let [run] = history.as_slice() else {
        return Err(format!("one run: {history:?}").into());
    };
    assert_eq!(
        (
            run.get("slot"),
            run.get("requested_by"),
            run.pointer("/state/kind")
        ),
        (
            Some(&Value::Null),
            Some(&json!(format!("cli:{USER}"))),
            Some(&json!("succeeded"))
        ),
        "{run}"
    );
    let entries = audited(&env)?;
    let audited_run = entries
        .iter()
        .find(|entry| entry.get("action") == Some(&json!("schedule.run")))
        .ok_or("no schedule.run entry")?;
    assert_eq!(
        audited_run.pointer("/params_redacted/requested_by"),
        Some(&json!(format!("cli:{USER}")))
    );
    handle.shutdown().await?;
    Ok(())
}

/// Todo 16: a reboot schedule needs `--confirm-destructive <router>` to be added and
/// to run now; `--yes` does not stand in for it, and nothing is sent without it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reboot_needs_the_destructive_confirmation() -> TestResult {
    let (env, handle) = fixture("admin").await?;
    let add = [
        "--json",
        "--router",
        ROUTER,
        "--yes",
        "scheduled",
        "add",
        "--name",
        "Restart",
        "--days",
        "sun",
        "--at",
        "04:00",
        "--reboot",
    ];
    let unconfirmed = expect(&env, 10, &add)?;
    let mut confirmed = vec!["--confirm-destructive", ROUTER];
    confirmed.extend_from_slice(&add);
    let added: Value = serde_json::from_str(&expect(&env, 0, &confirmed)?.stdout)?;
    let id = id_of(&added)?;

    let refused = expect(&env, 10, &["--json", "--yes", "scheduled", "run-now", &id])?;

    assert_eq!(failure_kind(&unconfirmed)?, "policy");
    assert_eq!(failure_kind(&refused)?, "policy");
    assert!(
        commands(&handle)
            .iter()
            .all(|line| !line.contains("reboot")),
        "{:?}",
        commands(&handle)
    );
    assert_eq!(runs(&env, &id)?, Vec::<Value>::new(), "no run recorded");
    handle.shutdown().await?;
    Ok(())
}

/// Todo 16: a run-now on a router whose lease another process holds ends busy at once.
///
/// It exits with the busy code, records the run skipped `router_busy` and changes
/// nothing; a retry would first wait a minute.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_busy_router_is_not_retried() -> TestResult {
    let (env, handle) = fixture("admin").await?;
    register_phone(&env)?;
    let id = add_switch(&env)?;
    let held = StateStore::open(&env.state_dir())?.try_lease(ROUTER)?;
    let started = Instant::now();

    let busy = expect(&env, 5, &["--json", "--yes", "scheduled", "run-now", &id])?;

    assert!(started.elapsed() < BUSY_RETRY, "no retry");
    drop(held);
    assert_eq!(failure_kind(&busy)?, "conflict");
    let history = runs(&env, &id)?;
    let [run] = history.as_slice() else {
        return Err(format!("one run: {history:?}").into());
    };
    assert_eq!(
        run.get("state"),
        Some(&json!({"kind": "skipped", "reason": "router_busy"}))
    );
    let line = format!("ip hotspot host {PHONE} policy {POLICY}");
    assert!(!handle.running_config_text().contains(&line));
    handle.shutdown().await?;
    Ok(())
}
