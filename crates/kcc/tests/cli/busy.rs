//! Applies onto a router whose lease another process holds.

use core::error::Error;
use std::{fs, io, path::Path};

use kcc_app::{audit::read_entries, persist::StateStore, workflow::WorkflowError};
use kcc_testkit::{
    DEFAULT_PASSWORD, FakeRouter, migration,
    model::{Firmware, Model, Profile},
};
use serde_json::Value;

use super::support::{Env, TestResult, router};

/// A saved source configuration with one interface description and one DNS upstream.
const SOURCE: &str = "! $$$ Model: Keenetic Giga\n! $$$ Version: 5.1.0\ninterface Bridge11\n description migrated-1\n!\ndns-proxy tls upstream 1.1.1.1 853\n!\n";

/// Number of job records in the state directory.
fn jobs(state: &Path) -> Result<usize, io::Error> {
    match fs::read_dir(state.join("jobs")) {
        Ok(entries) => Ok(entries.count()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    }
}

/// Number of `router_busy` refusals audited.
fn busy_refusals(state: &Path) -> Result<usize, Box<dyn Error>> {
    Ok(read_entries(state)?
        .iter()
        .filter(|entry| {
            entry.action == "cli.refused"
                && entry.outcome == "refused"
                && entry.params_redacted.get("reason").and_then(Value::as_str)
                    == Some("router_busy")
        })
        .count())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn busy_router_refuses_every_apply_before_a_job_exists() -> TestResult {
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some("router".to_owned());
    let (address, handle) = FakeRouter::builder(Profile::new(Model::Kn1811, Firmware::V5_1)?)
        .build()?
        .with_migration(scenario)
        .serve(([127, 0, 0, 1], 0).into())
        .await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("target", address, &password))?;
    let source = format!("file:{}", env.write("source.txt", SOURCE)?.display());
    let plan_path = env.path("plan.json");
    let plan = plan_path.to_str().ok_or("non-UTF-8 path")?;
    let planned = env.kcc(&["migrate", "plan", "--from", &source, "--out", plan])?;
    assert_eq!(planned.code, 0_i32, "{planned:?}");
    let captured = env.kcc(&[
        "preset",
        "capture",
        "--from",
        &source,
        "--groups",
        "dns-secure",
        "--name",
        "dns",
    ])?;
    assert_eq!(captured.code, 0_i32, "{captured:?}");
    let state = env.state_dir();
    let held = StateStore::open(&state)?.try_lease("target")?;
    let busy = WorkflowError::RouterBusy {
        actor: "another process".to_owned(),
    }
    .to_string();
    let job_records = jobs(&state)?;
    let commands: [&[&str]; 3] = [
        &[
            "--router", "target", "preset", "apply", "dns", "--yes", "--finish", "save",
        ],
        &[
            "copy",
            "--from",
            &source,
            "--to",
            "target",
            "--groups",
            "dns-secure",
            "--yes",
            "--finish",
            "save",
        ],
        &[
            "migrate", "apply", "--from", &source, "--plan", plan, "--yes",
        ],
    ];
    for (done, args) in commands.into_iter().enumerate() {
        let refused = env.kcc(args)?;

        assert_eq!(refused.code, 5_i32, "{args:?}: {refused:?}");
        assert!(refused.stderr.contains(&busy), "{args:?}: {refused:?}");
        assert_eq!(busy_refusals(&state)?, done + 1, "{args:?}: one refusal");
        assert_eq!(jobs(&state)?, job_records, "{args:?}: no job record");
    }
    drop(held);
    handle.shutdown().await?;
    Ok(())
}
