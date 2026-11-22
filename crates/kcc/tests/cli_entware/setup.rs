//! `kcc entware setup`: the job runs to the installer's success line, reports its progress
//! and leaves the configuration unsaved.

use kcc_i18n::keys;
use serde_json::Value;

use super::{
    lab::{AARCH64_URL, DRIVE, Lab, MIPSEL_URL, Router, SAVE, en},
    support::TestResult,
};

/// Todo 13: on an aarch64 router the setup sends the aarch64 installer and never saves.
///
/// The one JSON document carries the job's progress, ending in the unsaved `done` step.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_is_one_document_and_never_saves() -> TestResult {
    let lab = Lab::spawn("admin").await?;

    let done = lab.json(&[
        "--confirm-destructive",
        "lab-1",
        "entware",
        "setup",
        "--drive",
        DRIVE,
    ])?;

    let object = done.as_object().ok_or("not an object")?;
    let mut fields = object.keys().map(String::as_str).collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(
        fields,
        ["job_id", "message", "progress", "status", "unsaved"],
        "{done}"
    );
    assert_eq!(
        done.get("status"),
        Some(&Value::from("completed")),
        "{done}"
    );
    assert_eq!(done.get("unsaved"), Some(&Value::Bool(true)), "{done}");
    let last = done
        .get("progress")
        .and_then(Value::as_array)
        .and_then(|steps| steps.last())
        .ok_or("no progress")?;
    assert_eq!(last.get("step"), Some(&Value::from("done")), "{done}");
    assert_eq!(last.get("unsaved"), Some(&Value::Bool(true)), "{done}");
    let commands = lab.commands();
    let install = format!("opkg disk {DRIVE} {AARCH64_URL}");
    assert!(commands.contains(&install), "{commands:?}");
    assert!(!commands.iter().any(|line| line == SAVE), "{commands:?}");
    lab.shutdown().await
}

/// Todo 13: on a KN-1010 (`mips`) the chosen `--arch` selects the installer; the human
/// output notes each step on stderr and ends with the unsaved notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_takes_the_chosen_installer_and_reports_progress() -> TestResult {
    let lab = Lab::serve(Router::Kn1010, "admin").await?;

    let run = lab.run(&[
        "--confirm-destructive",
        "lab-1",
        "entware",
        "setup",
        "--drive",
        "internal",
        "--arch",
        "mipsel",
    ])?;

    assert_eq!(run.code, 0_i32, "{run:?}");
    assert!(
        run.stdout
            .contains(&en(keys::CLI_ENTWARE_SETUP_DONE, &[("router", "lab-1")])),
        "{run:?}"
    );
    let waiting = en(keys::CLI_ENTWARE_STEP_VERIFY, &[]);
    assert!(run.stderr.contains(&waiting), "{run:?}");
    let commands = lab.commands();
    let install = format!("opkg disk storage:/ {MIPSEL_URL}");
    assert!(commands.contains(&install), "{commands:?}");
    assert!(!commands.iter().any(|line| line == SAVE), "{commands:?}");
    lab.shutdown().await
}

/// Todo 13: the setup runs within the 1 MiB main stack Windows gives the CLI.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_runs_within_a_one_mebibyte_main_stack() -> TestResult {
    let lab = Lab::spawn("admin").await?;
    let config = lab.env.path("kcc.toml");
    let kcc = [
        env!("CARGO_BIN_EXE_kcc"),
        "--config",
        config.to_str().ok_or("non-UTF-8")?,
    ];
    let setup = [
        "--json",
        "--confirm-destructive",
        "lab-1",
        "entware",
        "setup",
        "--drive",
        DRIVE,
    ];
    let launcher = ["-c", "ulimit -s 1024 && exec \"$0\" \"$@\""];
    let args = [&launcher[..], &kcc, &setup].concat();

    let run = super::support::finish(super::spawning::spawn(&mut lab.env.launch("sh", &args))?)?;

    assert_eq!(run.code, 0_i32, "{run:?}");
    lab.shutdown().await
}
