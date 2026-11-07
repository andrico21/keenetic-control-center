//! Diagnostic jobs, the component commit and the fail-safe keep-alive.

use kcc_app::audit::read_entries;
use serde_json::Value;

use super::{lab::Lab, support::TestResult};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ping_job_runs_to_completion_with_its_lines() -> TestResult {
    let lab = Lab::spawn("").await?;
    let done = lab.json(&["diagnostics", "ping", "192.0.2.1", "--count", "3"])?;
    assert_eq!(
        done.get("status"),
        Some(&Value::from("completed")),
        "{done}"
    );
    let lines = done
        .get("lines")
        .and_then(Value::as_array)
        .ok_or("no lines")?;
    assert!(!lines.is_empty(), "{done}");
    let human = lab.run(&["diagnostics", "traceroute", "192.0.2.1"])?;
    assert_eq!(human.code, 0_i32, "{human:?}");
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_probe_option_is_refused_before_the_job() -> TestResult {
    let lab = Lab::spawn("").await?;
    let run = lab.run(&["diagnostics", "ping", "192.0.2.1", "--time", "5"])?;
    assert_eq!(run.code, 4_i32, "{run:?}");
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn component_commit_needs_the_router_id_and_waits_for_the_reboot() -> TestResult {
    let lab = Lab::spawn("").await?;
    let unconfirmed = lab.run(&["--yes", "components", "commit"])?;
    assert_eq!(unconfirmed.code, 10_i32, "{unconfirmed:?}");
    let wrong = lab.run(&["--confirm-destructive", "prod-1", "components", "commit"])?;
    assert_eq!(wrong.code, 10_i32, "{wrong:?}");
    let entries = read_entries(&lab.env.state_dir())?;
    assert!(
        entries.is_empty(),
        "an unconfirmed commit reached the workflow: {entries:?}"
    );
    let done = lab.json(&["--confirm-destructive", "lab-1", "components", "commit"])?;
    assert_eq!(
        done.get("status"),
        Some(&Value::from("completed")),
        "{done}"
    );
    let info = lab.json(&["info"])?;
    assert_eq!(info.get("router"), Some(&Value::from("lab-1")), "{info}");
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keep_alive_without_a_native_timer_is_the_router_refusal() -> TestResult {
    // The fake reports no `show system mode`, so `config failsafe arm` schedules a reboot
    // instead of the native timer and the router refuses to restart a timer it lacks.
    let lab = Lab::spawn("").await?;
    let run = lab.run(&["config", "keep-alive"])?;
    assert_eq!(run.code, 6_i32, "{run:?}");
    assert_ne!(lab.fake.request_count(), 0);
    lab.shutdown().await
}
