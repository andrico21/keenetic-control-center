//! Rebooting component commit job execution.

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{
    jobs::{JobProgress, JobRunner},
    permissions::{Permission, Role},
    registry::{RouterRegistry, authorize},
    workflow::{ChangeSet, CliChangeRequest, CliCommand as ValidatedCli},
};
use kcc_catalog::{Catalog, HttpMethod};
use kcc_rci::capabilities::RouterInfo;
use serde_json::{Value, json};
use tokio::time::sleep;

use super::{CommitError, CommitProgress};
use crate::DomainError;

/// Maximum number of post-reboot reachability probes.
const REACHABILITY_ATTEMPTS: u8 = 40;
/// Delay between reachability probes; cancellation remains observable between probes.
const REACHABILITY_INTERVAL: Duration = Duration::from_millis(250);

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
        vec![ValidatedCli::new("components commit".to_owned(), validated)],
        Permission::Destructive,
        json!({"operation":"components commit"}),
    );
    let before = registry.poll_info(&router_name).await?;
    let before_progress = progress("committing", &before, None);
    let rebooting_progress = progress("rebooting", &before, None);
    let job_router = router_name.clone();
    jobs.start(
        "components.commit".to_owned(),
        Some(router_name),
        true,
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
            for attempt in 0..REACHABILITY_ATTEMPTS {
                if context.cancellation().is_cancelled() {
                    return Err("component commit cancelled".to_owned());
                }
                match registry.poll_info(&job_router).await {
                    Ok(after) => {
                        drop(Catalog::for_router(&after).map_err(|error| error.to_string())?);
                        context.progress(100);
                        context.structured_progress(JobProgress::Structured(progress(
                            "completed",
                            &before,
                            Some(&after),
                        )));
                        return Ok(());
                    }
                    Err(_error) if attempt.saturating_add(1) < REACHABILITY_ATTEMPTS => {
                        sleep(REACHABILITY_INTERVAL).await;
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
            Err("router did not return after component commit".to_owned())
        },
    )
    .await
    .map_err(CommitError::Job)
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
