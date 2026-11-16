//! Components domain integration coverage.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::jobs::{JobEvent, JobProgress, JobRunner, JobStatus};
use kcc_domain::components::{self, CommitError, QueueAction};
use kcc_testkit::{FaultInjection, model::Firmware};
use serde_json::Value;
use tokio::{sync::broadcast::Receiver, time::timeout};

use crate::support::{Fixture, PROFILES, TestResult, administrator};

/// The longest a test waits for one job event.
const EVENT_WAIT: Duration = Duration::from_secs(30);

/// The fake's component reboot window, plus one second.
const REBOOT: Duration = Duration::from_secs(6);

/// The progress a commit job reports once the router went down.
const DOWN: u8 = 60;

/// The next event of job `id` that `wanted` accepts, within [`EVENT_WAIT`].
async fn next_event(
    events: &mut Receiver<JobEvent>,
    id: &str,
    wanted: impl Fn(&JobEvent) -> bool + Send + Sync,
) -> TestResult<JobEvent> {
    timeout(EVENT_WAIT, async {
        loop {
            let event = events.recv().await?;
            if event.id == id && wanted(&event) {
                return TestResult::<JobEvent>::Ok(event);
            }
        }
    })
    .await?
}

/// The structured phase of `event`, when it carries one.
fn phase(event: &JobEvent) -> Option<&str> {
    match &event.detail {
        Some(JobProgress::Structured(value)) => value.get("phase").and_then(Value::as_str),
        Some(_) | None => None,
    }
}

/// Whether `event` ends its job.
fn terminal(event: &JobEvent) -> bool {
    event.status != JobStatus::Running
}

/// Stages installing `ftp` and removing `ipsec`, then starts the commit job.
async fn staged_commit(
    fixture: &Fixture,
) -> TestResult<(Arc<JobRunner>, Receiver<JobEvent>, String)> {
    for (action, name) in [
        (QueueAction::Install, "ftp"),
        (QueueAction::Remove, "ipsec"),
    ] {
        let operation = components::plan_queue(fixture.context(), action, name)?;
        let mut changes = fixture.changes().await?;
        drop(
            changes
                .apply_cli(components::change_request(&operation)?)
                .await?,
        );
        drop(changes);
    }
    let jobs = fixture.jobs().await?;
    let mut events = jobs.subscribe();
    let changes = fixture.changes().await?;
    let id = components::start_commit_job(
        &jobs,
        fixture.registry(),
        "router".to_owned(),
        &administrator(),
        changes,
        &fixture.context().catalog,
        true,
    )
    .await?;
    drop(next_event(&mut events, &id, |event| phase(event) == Some("rebooting")).await?);
    Ok((jobs, events, id))
}

/// The installed components a `completed` progress payload reports.
fn after_components(event: &JobEvent) -> Vec<String> {
    match &event.detail {
        Some(JobProgress::Structured(value)) => value
            .get("after_components")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(_) | None => Vec::new(),
    }
}

#[tokio::test]
async fn commit_survives_reboot_and_reports_redetected_state() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn_clocked(firmware).await?;
        let (_jobs, mut events, id) = staged_commit(&fixture).await?;

        drop(next_event(&mut events, &id, |event| event.progress == DOWN).await?);
        fixture.advance(REBOOT)?;
        let completed =
            next_event(&mut events, &id, |event| phase(event) == Some("completed")).await?;
        let ended = next_event(&mut events, &id, terminal).await?;

        assert_eq!(ended.status, JobStatus::Completed, "{firmware}");
        assert_eq!(ended.progress, 100);
        let reported = after_components(&completed);
        assert!(reported.iter().any(|name| name == "ftp"), "{firmware}");
        assert!(!reported.iter().any(|name| name == "ipsec"), "{firmware}");
        let after = fixture.registry().poll_info("router").await?;
        let updated = if firmware == Firmware::V4_3 {
            "4.3.10"
        } else {
            "5.1.4"
        };
        assert_eq!(after.version.title.as_deref(), Some(updated));
        assert!(after.components.contains("ftp"));
        assert!(!after.components.contains("ipsec"));
        fixture.shutdown().await?;
    }
    Ok(())
}

/// C-11: a router still answering after `components commit` does not complete the job.
///
/// A real router answers while it downloads and flashes. The job completes only after one failed probe (the router went down) and a successful
/// one after it, and reports the components the restarted router found.
#[tokio::test]
async fn a_commit_completes_only_after_the_router_restarts() -> TestResult {
    for firmware in PROFILES {
        let faults = FaultInjection::default().components_commit_answers(2);
        let fixture = Fixture::spawn_clocked_with_faults(firmware, faults).await?;
        let (_jobs, mut events, id) = staged_commit(&fixture).await?;

        let first = next_event(&mut events, &id, |event| {
            event.progress >= DOWN || terminal(event)
        })
        .await?;
        assert_eq!(
            (first.status, first.progress),
            (JobStatus::Running, DOWN),
            "{firmware}: ended before the router went down"
        );
        fixture.advance(REBOOT)?;
        let completed =
            next_event(&mut events, &id, |event| phase(event) == Some("completed")).await?;
        let reported = after_components(&completed);
        assert!(reported.iter().any(|name| name == "ftp"), "{firmware}");
        assert!(!reported.iter().any(|name| name == "ipsec"), "{firmware}");
        let ended = next_event(&mut events, &id, terminal).await?;
        assert_eq!(ended.status, JobStatus::Completed, "{firmware}");
        fixture.shutdown().await?;
    }
    Ok(())
}

/// C-11: a router that restarts without the staged component changes fails the job.
#[tokio::test]
async fn a_commit_that_lost_the_staged_changes_fails() -> TestResult {
    for firmware in PROFILES {
        let faults = FaultInjection::default().components_commit_discards(true);
        let fixture = Fixture::spawn_clocked_with_faults(firmware, faults).await?;
        let (_jobs, mut events, id) = staged_commit(&fixture).await?;

        drop(
            next_event(&mut events, &id, |event| {
                event.progress >= DOWN || terminal(event)
            })
            .await?,
        );
        fixture.advance(REBOOT)?;
        let ended = next_event(&mut events, &id, terminal).await?;

        assert_eq!(ended.status, JobStatus::Failed, "{firmware}");
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn unconfirmed_commit_sends_no_request() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn_clocked(firmware).await?;
        let jobs = fixture.jobs().await?;
        let changes = fixture.changes().await?;
        let before = fixture.handle().request_count();
        let result = components::start_commit_job(
            &jobs,
            fixture.registry(),
            "router".to_owned(),
            &administrator(),
            changes,
            &fixture.context().catalog,
            false,
        )
        .await;
        assert!(matches!(result, Err(CommitError::ConfirmationRequired)));
        assert_eq!(fixture.handle().request_count(), before);
        fixture.shutdown().await?;
    }
    Ok(())
}
