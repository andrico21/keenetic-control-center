//! Protected replay ordering and per-line progress.

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{
    jobs::{JobContext, JobProgress},
    permissions::Permission,
    workflow::ReplayOutcome,
};
use kcc_catalog::Catalog;
use kcc_domain::{
    RouterCtx,
    configuration::{SafetyMode, SafetyNet},
};
use serde_json::json;

use super::{Applier, ApplyError, dispatch::submit, finish, reconnect::complete_line, verify};

/// Executes additions, selected removals, and management changes before read-back.
///
/// # Errors
/// Returns the first critical failure or final verification failure.
// NOT cancel-safe: successfully submitted lines remain under router recovery.
pub(super) async fn run(applier: &mut Applier, context: &JobContext) -> Result<(), ApplyError> {
    if applier.report.finished || applier.report.verified {
        return Err(ApplyError::Validation);
    }
    let client = applier.changes.client();
    let catalog = Catalog::for_router(
        &client
            .detect()
            .await
            .map_err(|_error| ApplyError::Unreachable)?,
    )
    .map_err(|_error| ApplyError::Validation)?;
    let lines = applier
        .plan
        .phases
        .additive
        .iter()
        .chain(&applier.plan.phases.prune)
        .cloned()
        .collect::<Vec<_>>();
    for (offset, line) in lines.iter().enumerate() {
        if context.cancellation().is_cancelled() {
            return Err(ApplyError::Cancelled);
        }
        if applier.options.clock.now().saturating_sub(applier.armed_at) >= Duration::from_secs(60) {
            keep_alive(applier).await?;
        }
        let result = submit(applier, &catalog, line).await?;
        let [outcome] = result.outcomes.as_slice() else {
            return Err(ApplyError::Workflow);
        };
        let percent = offset
            .saturating_add(1)
            .saturating_mul(90)
            .checked_div(lines.len())
            .unwrap_or(90);
        context.progress(u8::try_from(percent).unwrap_or(90));
        context.structured_progress(JobProgress::Structured(
            json!({"source_index":line.source_index,"outcome":outcome}),
        ));
        match *outcome {
            ReplayOutcome::Applied => applier.report.applied.push(line.source_index),
            ReplayOutcome::Rejected => {
                applier.report.failed.push(line.source_index);
                return Err(ApplyError::Stopped);
            }
            ReplayOutcome::Indeterminate | _ => return finish::recover(applier).await,
        }
        complete_line(applier, line, result.completion).await?;
        if offset.saturating_add(1).is_multiple_of(50)
            || applier
                .options
                .clock
                .now()
                .saturating_sub(applier.armed_at)
                .as_secs()
                >= 60
        {
            keep_alive(applier).await?;
        }
    }
    management(applier, &catalog, context).await?;
    keep_alive(applier).await?;
    verify::run(applier).await?;
    context.progress(100);
    Ok(())
}

/// Runs connectivity changes only after every addition and removal applied.
///
/// # Errors
/// Returns the first management rejection, audit failure, or recovery outcome.
// NOT cancel-safe: a management write may change credentials or the reachable origin.
async fn management(
    applier: &mut Applier,
    catalog: &Catalog,
    context: &JobContext,
) -> Result<(), ApplyError> {
    let lines = applier.plan.phases.management.clone();
    for line in &lines {
        if context.cancellation().is_cancelled() {
            return Err(ApplyError::Cancelled);
        }
        keep_alive(applier).await?;
        let result = submit(applier, catalog, line).await?;
        context.structured_progress(JobProgress::Structured(
            json!({"source_index":line.source_index,"outcomes":result.outcomes}),
        ));
        match result.outcomes.as_slice() {
            [ReplayOutcome::Applied] => applier.report.applied.push(line.source_index),
            [ReplayOutcome::Rejected] => {
                applier.report.failed.push(line.source_index);
                return Err(ApplyError::Stopped);
            }
            [ReplayOutcome::Indeterminate] => return finish::recover(applier).await,
            _ => return Err(ApplyError::Workflow),
        }
        complete_line(applier, line, result.completion).await?;
    }
    Ok(())
}

/// Renews the recovery timer under the run's `Migrate` without persisting configuration.
///
/// # Errors
/// Returns a protected workflow error.
// NOT cancel-safe: a transmitted keep-alive may renew the timer before cancellation.
pub(super) async fn keep_alive(applier: &mut Applier) -> Result<(), ApplyError> {
    let client = applier.changes.client();
    let catalog = Catalog::for_router(
        &client
            .detect()
            .await
            .map_err(|_error| ApplyError::Unreachable)?,
    )
    .map_err(|_error| ApplyError::Validation)?;
    let ctx = RouterCtx::new(Arc::clone(&client), catalog);
    match applier.mode {
        SafetyMode::Router => {
            drop(
                SafetyNet::keep_alive(&mut applier.changes, &ctx, Permission::Migrate)
                    .await
                    .map_err(|_error| ApplyError::Workflow)?,
            );
        }
        SafetyMode::ScheduledReboot => {
            drop(
                SafetyNet::arm(
                    &mut applier.changes,
                    &ctx,
                    applier.mode,
                    applier.options.safety_seconds,
                    Permission::Migrate,
                )
                .await
                .map_err(|_error| ApplyError::Workflow)?,
            );
        }
        _ => return Err(ApplyError::Validation),
    }
    applier.armed_at = applier.options.clock.now();
    Ok(())
}
