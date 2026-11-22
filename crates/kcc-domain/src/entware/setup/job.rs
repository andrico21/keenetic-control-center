//! The setup job body: components, install, log verification, read-back.

use core::fmt::Display;

use kcc_app::{
    jobs::{JobContext, JobProgress},
    workflow::{ChangeSet, CliChangeRequest, WorkflowError},
};
use serde_json::{Value, json};

use super::{Plan, SAVE_NOTICE, Setup, SetupFailure, SetupProgress, SetupStep, watch};
use crate::{
    RouterCtx,
    components::{self, commit::run_commit},
    entware,
};

impl Setup {
    /// Runs the setup `plan` with `changes`.
    ///
    /// # Errors
    ///
    /// The job failure text, a [`SetupFailure`].
    // NOT cancel-safe: it sends router changes (a rebooting commit, `opkg disk`).
    pub(super) async fn run(
        self,
        context: JobContext,
        begun: ChangeSet,
        plan: Plan,
    ) -> Result<(), String> {
        let mut changes = match plan.commit {
            Some(commit) => {
                report(&context, 5, &SetupProgress::at(SetupStep::Components, None));
                self.components(&context, (begun, plan.queue), commit)
                    .await?
            }
            None => begun,
        };
        let router = RouterCtx::new(changes.client(), self.catalog.clone());
        let baseline = watch::baseline(&router, &self.router)
            .await
            .map_err(|failure| failure.to_string())?;
        if context.cancellation().is_cancelled() {
            return Err(SetupFailure::CancelledBeforeInstall.to_string());
        }
        report(&context, 70, &SetupProgress::at(SetupStep::Install, None));
        drop(
            changes
                .apply_cli(plan.install)
                .await
                .map_err(|error| failed(SetupStep::Install, &error))?,
        );
        report(&context, 72, &SetupProgress::at(SetupStep::Verify, None));
        watch::installed(&context, &router, &self.router, baseline).await?;
        report(
            &context,
            95,
            &SetupProgress::at(SetupStep::ReadBack, Some(5)),
        );
        let settings = entware::read_settings(&router)
            .await
            .map_err(|error| failed(SetupStep::ReadBack, &error))?;
        if settings.disk.as_deref() != Some(plan.disk.as_str()) {
            return Err(SetupFailure::ReadBackMismatch.to_string());
        }
        context.structured_progress(JobProgress::Structured(serialized(&SetupProgress {
            step: SetupStep::Done,
            installer_step: Some(5),
            unsaved: Some(true),
            message: Some(SAVE_NOTICE),
        })));
        drop(changes);
        if context.cancellation().is_cancelled() {
            return Err(SetupFailure::CancelledAfterInstall.to_string());
        }
        Ok(())
    }

    /// Queues the missing components, commits them, waits for the restart, and begins the
    /// fresh change set the rest of the job uses.
    ///
    /// # Errors
    ///
    /// [`SetupFailure::ComponentsInstalled`] when another writer holds the router's lease
    /// after the restart, otherwise the failure of the queue, the commit or the restart.
    // NOT cancel-safe: it sends the rebooting component commit.
    async fn components(
        &self,
        context: &JobContext,
        (changes, queue): (ChangeSet, Vec<CliChangeRequest>),
        commit: CliChangeRequest,
    ) -> Result<ChangeSet, String> {
        let mut queued = changes;
        for request in queue {
            drop(
                queued
                    .apply_cli(request)
                    .await
                    .map_err(|error| failed(SetupStep::Components, &error))?,
            );
        }
        let router = RouterCtx::new(queued.client(), self.catalog.clone());
        let staged = components::read_pending(&router)
            .await
            .map_err(|error| failed(SetupStep::Components, &error))?;
        let before = self
            .registry
            .poll_info(&self.router)
            .await
            .map_err(|error| failed(SetupStep::Components, &error))?;
        drop(
            run_commit(
                context,
                &self.registry,
                &self.router,
                queued,
                commit,
                &staged,
                before,
            )
            .await
            .map_err(|reason| {
                SetupFailure::Step {
                    step: SetupStep::Components,
                    reason,
                }
                .to_string()
            })?,
        );
        match self
            .workflow
            .begin(&self.router, self.actor.clone(), &self.role, false)
            .await
        {
            Ok(fresh) => Ok(fresh),
            Err(WorkflowError::RouterBusy { actor: _ }) => {
                Err(SetupFailure::ComponentsInstalled.to_string())
            }
            Err(error) => Err(failed(SetupStep::Components, &error)),
        }
    }
}

/// Reports `progress` at `percent`.
pub(super) fn report(context: &JobContext, percent: u8, progress: &SetupProgress) {
    context.progress(percent);
    context.structured_progress(JobProgress::Structured(serialized(progress)));
}

/// The progress payload.
fn serialized(progress: &SetupProgress) -> Value {
    serde_json::to_value(progress).unwrap_or_else(|_error| json!({"step":progress.step}))
}

/// The failure text of `error` in `step`.
pub(super) fn failed(step: SetupStep, error: &impl Display) -> String {
    SetupFailure::Step {
        step,
        reason: error.to_string(),
    }
    .to_string()
}
