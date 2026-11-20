//! The policy switch: running configuration only, refusals that send nothing, a busy
//! router and the bracket count.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{
    accounts::{Clock as _, SystemClock},
    audit::{Actor, ActorKind},
    schedules::ledger::{RunOutcome, Trigger},
};
use serde_json::Value;
use tokio::time::timeout;

use super::{Bench, PHONE, VISITOR, WAIT, admin, now, switch};
use crate::server_schedules::{
    Timings,
    run::{Report, run_once},
    tests::rig::{ROUTER, TestResult},
};

/// Todo 13: a scheduled policy switch sets the host's policy in the running and not in
/// the startup configuration, and is audited as `system`/`schedule:<id>`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_policy_switch_changes_only_the_running_configuration() -> TestResult {
    let id = "0000000000000a01";
    let bench = Bench::start(Timings::default(), vec![switch(id, PHONE, "Policy0")?]).await?;
    bench.register_phone().await?;

    let report = bench.run(id, now()).await?;

    let Report::Finished(RunOutcome::Succeeded { unsaved, checksum }) = report else {
        return Err(format!("{report:?}").into());
    };
    assert!(unsaved && checksum.is_some(), "{unsaved} {checksum:?}");
    let line = format!("ip hotspot host {PHONE} policy Policy0");
    let fake = bench.fake()?;
    assert!(
        fake.running_config_text().contains(&line),
        "{}",
        fake.running_config_text()
    );
    assert!(!fake.startup_config_text().contains(&line), "never saved");
    let entries = bench.run_entries().await?;
    let [entry] = entries.as_slice() else {
        return Err(format!("one schedule.run entry: {entries:?}").into());
    };
    assert_eq!(
        (
            entry.actor.kind,
            entry.actor.id.as_str(),
            entry.outcome.as_str()
        ),
        (ActorKind::System, "schedule:0000000000000a01", "success")
    );
    assert_eq!(entry.target.as_deref(), Some("policy_switch"));
    assert_eq!(
        entry.params_redacted.get("requested_by"),
        Some(&Value::from("web:alice"))
    );
    Ok(())
}

/// Todo 13: an unregistered client fails `client_unknown` and is not registered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unregistered_client_is_refused() -> TestResult {
    let id = "0000000000000a02";
    let bench = Bench::start(Timings::default(), vec![switch(id, VISITOR, "Policy0")?]).await?;

    let report = bench.run(id, now()).await?;

    assert_eq!(
        report,
        Report::Finished(RunOutcome::Failed {
            code: "client_unknown".to_owned()
        })
    );
    let commands = bench.commands()?;
    assert!(
        !commands
            .iter()
            .any(|command| command.contains("known host")),
        "{commands:?}"
    );
    Ok(())
}

/// Todo 13: an unknown policy fails `policy_unknown` and sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_policy_sends_nothing() -> TestResult {
    let id = "0000000000000a03";
    let bench = Bench::start(Timings::default(), vec![switch(id, PHONE, "Policy9")?]).await?;
    bench.register_phone().await?;
    let before = bench.commands()?.len();

    let report = bench.run(id, now()).await?;

    assert_eq!(
        report,
        Report::Finished(RunOutcome::Failed {
            code: "policy_unknown".to_owned()
        })
    );
    let sent = bench.commands()?;
    assert_eq!(sent.len(), before, "{sent:?}");
    Ok(())
}

/// Todo 13: a router whose lease another actor holds is tried again and the run ends
/// skipped `router_busy`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_lease_is_retried_then_skipped() -> TestResult {
    let id = "0000000000000a07";
    let timings = Timings {
        busy_retry: Duration::from_secs(1),
        busy_window: Duration::from_secs(2),
        ..Timings::default()
    };
    let bench = Bench::start(timings, vec![switch(id, PHONE, "Policy0")?]).await?;
    let other = Actor::new(ActorKind::Cli, "cli:other".to_owned());
    let _held = bench.workflow.reserve(ROUTER, &other, &admin())?;
    let slot = i64::try_from(SystemClock::default().unix_seconds())?;

    let report = bench.run(id, Trigger::Slot(slot)).await?;

    assert_eq!(
        report,
        Report::Finished(RunOutcome::Skipped {
            reason: "router_busy".to_owned()
        })
    );
    assert!(
        bench.recorder.jobs().len() >= 2,
        "tried again: {:?}",
        bench.recorder.jobs()
    );
    let commands = bench.commands()?;
    assert!(
        !commands
            .iter()
            .any(|command| command.contains("ip hotspot")),
        "{commands:?}"
    );
    Ok(())
}

/// Todo 13: a policy run held by a stalled router is counted as an open bracket until it
/// ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_policy_run_holds_a_bracket() -> TestResult {
    let id = "0000000000000a08";
    let bench = Bench::start(Timings::default(), vec![switch(id, PHONE, "Policy0")?]).await?;
    bench.register_phone().await?;
    let mut stall = bench.fake()?.stall();
    let deps = Arc::clone(&bench.deps);
    let running = tokio::spawn(async move { run_once(&deps, id, now()).await });

    let held = timeout(WAIT, stall.held()).await?;
    let open = bench.workflow.brackets().count();
    drop(stall);
    let report = timeout(WAIT, running).await??;

    assert!(held, "a request reached the stalled router");
    assert_eq!(open, 1, "counted while held");
    assert_eq!(bench.workflow.brackets().count(), 0, "released after");
    assert!(
        matches!(
            report,
            Report::Finished(RunOutcome::Succeeded {
                unsaved: _,
                checksum: _
            })
        ),
        "{report:?}"
    );
    Ok(())
}
