//! The backup and the reboot.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{
    jobs::JobStatus,
    schedules::{ledger::RunOutcome, model::Schedule},
};
use serde_json::json;
use tokio::time::timeout;

use super::{Bench, WAIT, now};
use crate::server_schedules::{
    Timings,
    lines::LineKind,
    run::{Report, run_once},
    tests::rig::{ROUTER, TestResult, schedule},
};

/// Todo 13: a scheduled backup stores the startup configuration as `scheduled-<id>`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backup_is_stored_under_the_schedule() -> TestResult {
    let id = "0000000000000a04";
    let backup = schedule(id, (&["mon"], 3, 0, "UTC"), &json!({"kind": "backup"}), 0)?;
    let bench = Bench::start(Timings::default(), vec![backup]).await?;

    let report = bench.run(id, now()).await?;

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
    let names = bench
        .backups
        .list(ROUTER)?
        .into_iter()
        .map(|info| info.name)
        .collect::<Vec<_>>();
    assert!(
        names
            .iter()
            .any(|name| name.ends_with("-scheduled-0000000000000a04.txt")),
        "{names:?}"
    );
    Ok(())
}

/// Reboot waits short enough for a test.
fn quick_reboot() -> Timings {
    Timings {
        reboot_probe: Duration::from_secs(2),
        reboot_wait: Duration::from_secs(6),
        ..Timings::default()
    }
}

/// A reboot schedule.
fn reboot(id: &str) -> TestResult<Schedule> {
    schedule(id, (&["mon"], 3, 0, "UTC"), &json!({"kind": "reboot"}), 0)
}

/// Todo 13: a reboot restarts the router, mutes it first, and succeeds once it answers
/// with a fresh uptime.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reboot_succeeds_when_the_router_comes_back() -> TestResult {
    let id = "0000000000000a05";
    let bench = Bench::start(quick_reboot(), vec![reboot(id)?]).await?;

    let report = bench.run(id, now()).await?;

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
    assert!(
        bench
            .commands()?
            .iter()
            .any(|command| command == "system reboot"),
        "the router was restarted"
    );
    assert_eq!(
        bench
            .recorder
            .mutes()
            .into_iter()
            .map(|(router, _until)| router)
            .collect::<Vec<_>>(),
        vec![ROUTER.to_owned()]
    );
    assert!(
        bench
            .recorder
            .lines()
            .iter()
            .any(|(_id, kind)| *kind == LineKind::Restarted)
    );
    Ok(())
}

/// Todo 13: a router that stays down after the restart fails `did_not_come_back`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_router_that_stays_down_did_not_come_back() -> TestResult {
    let id = "0000000000000a06";
    let mut bench = Bench::start(quick_reboot(), vec![reboot(id)?]).await?;
    let mut events = bench.jobs.subscribe();
    let deps = Arc::clone(&bench.deps);
    let running = tokio::spawn(async move { run_once(&deps, id, now()).await });

    timeout(WAIT, async {
        while let Ok(event) = events.recv().await {
            if event.status == JobStatus::Completed {
                break;
            }
        }
    })
    .await?;
    bench
        .router
        .take()
        .ok_or("the router stopped")?
        .shutdown()
        .await?;
    let report = timeout(WAIT, running).await??;

    assert_eq!(
        report,
        Report::Finished(RunOutcome::Failed {
            code: "did_not_come_back".to_owned()
        })
    );
    Ok(())
}
