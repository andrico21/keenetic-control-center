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
///
/// # Errors
///
/// Returns an error when the role lacks the permission or the router scope, or the router
/// cannot be polled ([`CommitError::Registry`]), when the destructive change is not
/// confirmed ([`CommitError::ConfirmationRequired`]), when the catalog refuses the request
/// or the commit line does not render it, or when reading the pending components fails or
/// does not decode ([`CommitError::Domain`]), or when the job cannot be recorded or
/// started ([`CommitError::Job`]). Dispatch and read-back failures happen inside the job
/// and are reported through it.
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
    let request = commit_request(catalog)?;
    let staged: PendingComponents =
        read_show(&changes.client(), &["show", "components", "pending"]).await?;
    let before = registry.poll_info(&router_name).await?;
    let before_progress = serialized(&commit_progress("committing", &before, None));
    let job_router = router_name.clone();
    jobs.start(
        "components.commit".to_owned(),
        JobTarget::Write(router_name),
        async move |context| {
            context.progress(10);
            context.structured_progress(JobProgress::Structured(before_progress));
            let completed = run_commit(
                &context,
                &registry,
                &job_router,
                changes,
                request,
                &staged,
                before,
            )
            .await?;
            context.progress(100);
            context.structured_progress(JobProgress::Structured(serialized(&completed)));
            Ok(())
        },
    )
    .await
    .map_err(CommitError::Job)
}

/// The terminal `components commit` request, validated against `catalog`.
///
/// # Errors
///
/// [`DomainError::Validation`] when the catalog refuses the request, and
/// [`DomainError::Workflow`] when the commit line does not render it.
pub(crate) fn commit_request(catalog: &Catalog) -> Result<CliChangeRequest, DomainError> {
    let validated = catalog
        .validate("components commit", HttpMethod::Post, &json!({}))
        .map_err(|issues| DomainError::Validation { issues })?;
    Ok(CliChangeRequest::terminal(
        vec![ValidatedCli::new(
            "components commit".to_owned(),
            validated,
        )?],
        Permission::Destructive,
        json!({"operation":"components commit"}),
    ))
}

/// Commits the staged components and waits for the restarted router.
///
/// It applies the terminal `components commit` request, waits until the router restarted,
/// and checks that it has every staged installation and none of the staged removals; it
/// returns the `completed` progress. `before` is what the router reported before the
/// commit. The change set is consumed: its lease is released when this returns.
///
/// # Errors
///
/// The job failure text: the commit was refused or not sent, the router did not restart
/// within [`RESTART_LIMIT`], the job was cancelled, or the restarted router lacks the staged
/// changes.
// NOT cancel-safe: the commit may reboot the router before a dropped future learns of it.
pub(crate) async fn run_commit(
    context: &JobContext,
    registry: &RouterRegistry,
    router: &str,
    changes: ChangeSet,
    request: CliChangeRequest,
    staged: &PendingComponents,
    before: RouterInfo,
) -> Result<CommitProgress, String> {
    let mut active_changes = changes;
    drop(
        active_changes
            .apply_cli(request)
            .await
            .map_err(|error| error.to_string())?,
    );
    context.progress(30);
    context.structured_progress(JobProgress::Structured(serialized(&commit_progress(
        "rebooting",
        &before,
        None,
    ))));
    let after = timeout(RESTART_LIMIT, restarted(registry, router, context))
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
    drop(active_changes);
    Ok(commit_progress("completed", &before, Some(&after)))
}

/// Probes the router until one probe failed (it went down) and a later one succeeded,
/// and returns what the restarted router reports.
///
/// # Errors
///
/// The cancellation of the job.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, it only reads the router; dropped, it stops probing.
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

/// Typed commit state at `phase`.
fn commit_progress(phase: &str, before: &RouterInfo, after: Option<&RouterInfo>) -> CommitProgress {
    CommitProgress {
        phase: phase.to_owned(),
        before_firmware: before.version.title.clone(),
        after_firmware: after.and_then(|info| info.version.title.clone()),
        before_components: before.components.iter().cloned().collect(),
        after_components: after
            .into_iter()
            .flat_map(|info| info.components.iter().cloned())
            .collect(),
    }
}

/// Serializes typed commit state into a job progress payload.
fn serialized(payload: &CommitProgress) -> Value {
    serde_json::to_value(payload).unwrap_or_else(|_error| json!({"phase":payload.phase}))
}
