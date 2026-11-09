//! Components domain integration coverage.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use core::time::Duration;

use kcc_app::jobs::{JobProgress, JobStatus};
use kcc_domain::components::{self, CommitError, QueueAction};
use kcc_testkit::model::Firmware;

use crate::support::{Fixture, PROFILES, TestResult, administrator};

#[tokio::test]
async fn commit_survives_reboot_and_reports_redetected_state() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn_clocked(firmware).await?;
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

        let mut saw_rebooting = false;
        while !saw_rebooting {
            let event = events.recv().await?;
            saw_rebooting = event.id == id
                && matches!(&event.detail, Some(JobProgress::Structured(value)) if value.get("phase").and_then(serde_json::Value::as_str) == Some("rebooting"));
        }
        fixture.advance(Duration::from_secs(5))?;
        let completed = loop {
            let event = events.recv().await?;
            if event.id == id && event.status == JobStatus::Completed {
                break event;
            }
        };
        assert_eq!(completed.progress, 100);
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
