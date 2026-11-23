//! `kcc serve` runs the scheduler: a run a previous server left started is reported once
//! as interrupted and never run again; schedules of a router that is gone are paused and
//! reported; on SIGTERM the scheduler stops before the jobs are drained. The run path and
//! the timetable are proven by the scheduler's own tests; no test here waits for a slot.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process"
)]

#[path = "support/master_key.rs"]
mod master_key;
#[path = "serve_scheduled/process.rs"]
mod process;
#[path = "support/serve_port.rs"]
mod serve_port;
#[cfg(unix)]
#[expect(dead_code, reason = "the suite sends SIGHUP and SIGTERM only")]
#[path = "support/signal.rs"]
mod signal;
#[path = "support/spawning.rs"]
mod spawning;
#[path = "serve_scheduled/support.rs"]
mod support;

#[cfg(unix)]
use fluent_bundle::FluentArgs;
use kcc_app::schedules::{
    ledger::RunState,
    model::{PauseReason, ScheduleState},
};
#[cfg(unix)]
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use crate::support::{Fixture, ROUTER, TestResult, now};

/// Whether `state` is paused because the router is gone.
const fn router_removed(state: ScheduleState) -> bool {
    matches!(
        state,
        ScheduleState::Paused {
            reason: PauseReason::RouterRemoved,
            at: _
        }
    )
}

/// Todo 13: a run left started by a previous server is reported once as interrupted and
/// never run again: the router receives no `ip hotspot host` line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_started_run_is_reported_interrupted_once() -> TestResult {
    let fixture = Fixture::new().await?;
    let at = now()?;
    let id = fixture.schedule(ROUTER, at.saturating_sub(7_200))?;
    fixture.started(&id, at.saturating_sub(3_600))?;
    let server = fixture.serve()?;

    fixture.await_messages(1).await?;
    drop(server.finish());

    assert_eq!(fixture.runs(&id)?, vec![RunState::Interrupted]);
    let messages = fixture.messages();
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(
        messages.iter().all(|text| text.contains("phone night")),
        "{messages:?}"
    );
    let commands = fixture.router_commands();
    assert!(
        !commands.iter().any(|line| line.contains("ip hotspot host")),
        "{commands:?}"
    );
    Ok(())
}

/// Todo 13: a schedule whose router is not registered when the server starts is paused
/// `router_removed` and reported.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_schedule_of_an_unknown_router_is_paused_at_start() -> TestResult {
    let fixture = Fixture::new().await?;
    let id = fixture.schedule("gone", now()?.saturating_sub(7_200))?;
    let server = fixture.serve()?;

    fixture.await_messages(1).await?;
    drop(server.finish());

    assert!(router_removed(fixture.schedule_state(&id)?));
    assert!(fixture.runs(&id)?.is_empty(), "nothing ran");
    Ok(())
}

/// Todo 13: removing the router from `kcc.toml` and reloading pauses its schedule
/// `router_removed` and sends one message, the pause. SIGHUP is the reload of `kcc.toml`.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_the_router_pauses_its_schedule() -> TestResult {
    use core::time::Duration;

    let fixture = Fixture::new().await?;
    let id = fixture.schedule(ROUTER, now()?.saturating_sub(7_200))?;
    let server = fixture.serve()?;

    fixture.write_config(server.port(), false)?;
    server.hangup()?;
    fixture.await_messages(1).await?;
    let (status, _stderr) = server.terminate(Duration::from_secs(100))?;

    assert!(status.is_some(), "the server exits");
    assert!(router_removed(fixture.schedule_state(&id)?));
    let messages = fixture.messages();
    let mut paused = FluentArgs::new();
    paused.set("name", "phone night");
    paused.set("router", ROUTER);
    paused.set(
        "reason",
        tr(
            Locale::En,
            keys::NOTIFY_SCHEDULED_REASON_ROUTER_REMOVED,
            None,
        ),
    );
    let only = format!(
        "{} {}",
        tr(Locale::En, keys::NOTIFY_SCHEDULED_PAUSED, Some(&paused)),
        tr(Locale::En, keys::NOTIFY_SCHEDULED_UNSAVED, None)
    );
    assert_eq!(messages, vec![only]);
    Ok(())
}

/// Todo 13: on SIGTERM the scheduler stops before the jobs are drained.
///
/// The process exits within the stop budget. SIGTERM is the unix stop path; a health
/// answer first proves the listener's signal handler is in place.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_scheduler_stops_before_the_jobs_drain() -> TestResult {
    use core::time::Duration;

    use rustls::crypto::ring::default_provider;
    use serde_json::Value;

    let fixture = Fixture::new().await?;
    let server = fixture.serve()?;
    let _installed = default_provider().install_default();
    let health = reqwest::get(format!("http://127.0.0.1:{}/healthz", server.port())).await?;
    assert!(
        health.status().is_success(),
        "the server answers before the stop"
    );

    let (status, stderr) = server.terminate(Duration::from_secs(100))?;

    assert!(status.is_some_and(|code| code.success()), "{status:?}");
    let stopped = stderr.iter().position(|line| {
        serde_json::from_str::<Value>(line).is_ok_and(|event| {
            event.get("target").and_then(Value::as_str) == Some("kcc::scheduler")
                && event.pointer("/fields/event").and_then(Value::as_str) == Some("stopped")
        })
    });
    let drained = stderr.iter().position(|line| line.contains("jobs drained"));
    assert!(
        matches!((stopped, drained), (Some(first), Some(then)) if first < then),
        "stopped {stopped:?}, drained {drained:?}"
    );
    Ok(())
}
