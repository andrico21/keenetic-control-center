//! Rebooting component commit job execution.
//!
//! A router keeps answering for a while after `components commit`, while it downloads and
//! flashes, and only then restarts. The job therefore completes only after one failed
//! probe (the router went down) and a successful one after it, and only when the
//! restarted router has every staged installation and none of the staged removals.

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{
    jobs::{JobContext, JobProgress, JobRunner, JobTarget},
    permissions::{Permission, Role},
    registry::{RouterRegistry, authorize},
    workflow::{ChangeSet, CliChangeRequest, CliCommand as ValidatedCli},
};
use kcc_catalog::{Catalog, HttpMethod};
use kcc_rci::capabilities::RouterInfo;
use serde_json::{Value, json};
use tokio::time::{sleep, timeout};

use super::{CommitError, CommitProgress, PendingComponents};
use crate::{DomainError, read_show};

/// Delay between restart probes; cancellation remains observable between probes.
const PROBE_INTERVAL: Duration = Duration::from_secs(1);
/// The longest the job waits for the router to go down and come back: downloading,
/// flashing and restarting together.
const RESTART_LIMIT: Duration = Duration::from_mins(15);
/// The progress reported once a probe failed: the router went down to restart.
const DOWN_PROGRESS: u8 = 60;

/// Starts a confirmed destructive component commit job.
// NOT cancel-safe: the submitted commit may reboot the router before the job is recorded.
pub(super) async fn start(
    jobs: &Arc<JobRunner>,
    registry: Arc<RouterRegistry>,
    router_name: String,
    role: &Role,
    changes: ChangeSet,
    catalog: &Catalog,
    confirmed: bool,
) -> Result<String, CommitError> {
    authorize(role, Permission::Destructive, &router_name)?;
    if !confirmed {
        return Err(CommitError::ConfirmationRequired);
    }
    let validated = catalog
        .validate("components commit", HttpMethod::Post, &json!({}))
        .map_err(|issues| DomainError::Validation { issues })?;
    let request = CliChangeRequest::terminal(
        vec![
            ValidatedCli::new("components commit".to_owned(), validated)
                .map_err(DomainError::from)?,
        ],
        Permission::Destructive,
        json!({"operation":"components commit"}),
    );
    let staged: PendingComponents =
        read_show(&changes.client(), &["show", "components", "pending"]).await?;
    let before = registry.poll_info(&router_name).await?;
    let before_progress = progress("committing", &before, None);
    let rebooting_progress = progress("rebooting", &before, None);
    let job_router = router_name.clone();
    jobs.start(
        "components.commit".to_owned(),
        JobTarget::Write(router_name),
        async move |context| {
            context.progress(10);
            context.structured_progress(JobProgress::Structured(before_progress));
            let mut active_changes = changes;
            drop(
                active_changes
                    .apply_cli(request)
                    .await
                    .map_err(|error| error.to_string())?,
            );
            context.progress(30);
            context.structured_progress(JobProgress::Structured(rebooting_progress));
            let after = timeout(RESTART_LIMIT, restarted(&registry, &job_router, &context))
                .await
                .map_err(|_elapsed| "router did not restart after component commit".to_owned())??;
            drop(Catalog::for_router(&after).map_err(|error| error.to_string())?);
            let removed = staged
                .remove
                .iter()
                .all(|name| !after.components.contains(name));
            if !removed
                || !staged
                    .install
                    .iter()
                    .all(|name| after.components.contains(name))
            {
                return Err("the restarted router lacks the staged component changes".to_owned());
            }
            context.progress(100);
            context.structured_progress(JobProgress::Structured(progress(
                "completed",
                &before,
                Some(&after),
            )));
            Ok(())
        },
    )
    .await
    .map_err(CommitError::Job)
}

/// Probes the router until one probe failed (it went down) and a later one succeeded,
/// and returns what the restarted router reports.
///
/// # Errors
///
/// The cancellation of the job.
// cancel-safe: it only reads the router; dropped, it stops probing.
async fn restarted(
    registry: &RouterRegistry,
    router: &str,
    context: &JobContext,
) -> Result<RouterInfo, String> {
    let mut went_down = false;
    loop {
        if context.cancellation().is_cancelled() {
            return Err("component commit cancelled".to_owned());
        }
        match registry.poll_info(router).await {
            Ok(after) if went_down => return Ok(after),
            Ok(_still_up) => {}
            Err(_down) => {
                if !went_down {
                    went_down = true;
                    context.progress(DOWN_PROGRESS);
                }
            }
        }
        sleep(PROBE_INTERVAL).await;
    }
}

/// Serializes typed commit state into a job progress payload.
fn progress(phase: &str, before: &RouterInfo, after: Option<&RouterInfo>) -> Value {
    let payload = CommitProgress {
        phase: phase.to_owned(),
        before_firmware: before.version.title.clone(),
        after_firmware: after.and_then(|info| info.version.title.clone()),
        before_components: before.components.iter().cloned().collect(),
        after_components: after
            .into_iter()
            .flat_map(|info| info.components.iter().cloned())
            .collect(),
    };
    serde_json::to_value(payload).unwrap_or_else(|_error| json!({"phase":phase}))
}
