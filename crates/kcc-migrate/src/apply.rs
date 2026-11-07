//! Leased migration jobs with explicit persistence and rollback.
//!
//! Replay uses serial one-item `parse_batch` requests so a rejected critical line
//! prevents later lines from reaching the router. Recovery is renewed after every
//! 50-line boundary (and during slower work). This deliberately trades wire batching
//! efficiency for exact stop-on-error behavior.

#![expect(
    clippy::pub_use,
    reason = "public applier facade separates lifecycle and report types"
)]

mod agreements;
mod bootstrap;
pub(crate) mod command;
mod components;
mod dispatch;
mod drift;
mod execute;
mod finish;
mod normalize;
mod preflight;
mod raw;
mod reconnect;
mod types;
mod verify;

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{
    jobs::{JobContext, JobProgress, JobRunner},
    workflow::ChangeSet,
};
use kcc_domain::configuration::SafetyMode;
use kcc_rci::{RciClient, SecretBytes, auth::Credentials};
pub use raw::RawRestore;
use tokio::sync::oneshot;
#[expect(
    clippy::module_name_repetitions,
    reason = "the task specifies ApplyError and matching public apply types"
)]
pub use types::{
    ApplyError, ApplyOptions, ApplyReport, ApplyRequest, ApplySource, ApplyWarning, Clock,
    StopPolicy, SystemClock, WireGuardPublicKey,
};

/// Checks whether the migration applier can construct a protected request for `line`.
///
/// This is the planner's buildability boundary: catalog path presence alone is not enough for
/// context-leaf syntax that [`kcc_catalog::Catalog::validate_cli`] cannot represent yet.
#[inline]
#[must_use]
pub(crate) fn supports_line(catalog: &kcc_catalog::Catalog, line: &str) -> bool {
    command::build(catalog, line).is_ok()
}

use crate::planner::MigrationPlan;

/// Migration prepared under a router safety timer; dropping leaves router recovery armed.
#[derive(Debug)]
#[non_exhaustive]
pub struct Applier {
    /// Exclusive write lease retained through explicit finishing.
    changes: ChangeSet,
    /// Reviewed executable plan.
    plan: MigrationPlan,
    /// Original transport and credentials used after router rollback.
    original: Arc<RciClient>,
    /// Original startup configuration, also stored in the workflow's encrypted backup.
    backup: SecretBytes,
    /// Running configuration at preflight, retained for unplanned-difference checks.
    baseline: SecretBytes,
    /// Selected safety mechanism.
    mode: SafetyMode,
    /// Execution choices and injected clock.
    options: ApplyOptions,
    /// Credential selected by the management phase.
    credential: Option<Credentials>,
    /// Time of the most recent successful keep-alive.
    armed_at: Duration,
    /// Public value-free progress and verification report.
    report: ApplyReport,
}

impl Applier {
    /// Starts the complete apply as a persisted job, returning the lease through a completion channel.
    ///
    /// # Errors
    /// Returns job admission or persistence errors; preflight failures arrive on the channel.
    // NOT cancel-safe: once admitted, the persisted job continues independently.
    #[inline]
    pub async fn start(
        runner: &Arc<JobRunner>,
        request: ApplyRequest,
    ) -> Result<(String, oneshot::Receiver<Result<Self, ApplyError>>), ApplyError> {
        let router = request.target.clone();
        let locale = request.options.locale;
        let (sender, receiver) = oneshot::channel();
        let id = runner
            .start(
                "migration".to_owned(),
                Some(router),
                true,
                async move |context| {
                    let result = Self::prepare(request).await;
                    match result {
                        Ok(mut applier) => {
                            let execution = applier.apply(&context).await;
                            let job_result = execution
                                .map_err(|_error| applier.report.message(applier.options.locale));
                            // The caller receives the lease even on partial failure for explicit rollback.
                            drop(sender.send(Ok(applier)));
                            job_result
                        }
                        Err(error) => {
                            let report = ApplyReport {
                                failure: Some(error),
                                ..ApplyReport::default()
                            };
                            let message = report.message(locale);
                            drop(sender.send(Err(error)));
                            Err(message)
                        }
                    }
                },
            )
            .await
            .map_err(|_error| ApplyError::Job)?;
        Ok((id, receiver))
    }

    /// Checks preflight, backs up the target, and arms recovery before configuration changes.
    ///
    /// # Errors
    /// Returns typed preflight, authorization, drift, or safety-arm failures.
    // NOT cancel-safe: after arming, cancellation leaves the router safety timer active.
    #[inline]
    pub async fn prepare(request: ApplyRequest) -> Result<Self, ApplyError> {
        preflight::prepare(request).await
    }

    /// Executes the reviewed plan, reporting each line through its job context.
    ///
    /// # Errors
    /// Returns a stopped, verification, cancellation, or router rollback outcome.
    // NOT cancel-safe: completed writes remain unsaved under the armed timer.
    #[inline]
    pub async fn apply(&mut self, context: &JobContext) -> Result<(), ApplyError> {
        let result = execute::run(self, context).await;
        self.report.failure = result.as_ref().err().copied();
        context.structured_progress(JobProgress::OutputLine(
            self.report.message(self.options.locale),
        ));
        result
    }

    /// Returns value-free progress and verification results.
    #[inline]
    #[must_use]
    pub const fn report(&self) -> &ApplyReport {
        &self.report
    }

    /// Explicitly persists verified migration changes.
    ///
    /// # Errors
    /// Refuses unverified applies and reports conflicts, save, or audit failures.
    // NOT cancel-safe: a transmitted commit may persist changes before cancellation.
    #[inline]
    pub async fn commit(&mut self) -> Result<(), ApplyError> {
        finish::commit(self).await
    }

    /// Explicitly keeps verified changes running without saving them: the recovery timer
    /// is disarmed and the startup configuration stays as it was.
    ///
    /// # Errors
    /// Refuses unverified applies and reports conflicts or disarm failures.
    // NOT cancel-safe: a transmitted disarm may keep the changes before cancellation.
    #[inline]
    pub async fn keep_unsaved(&mut self) -> Result<(), ApplyError> {
        finish::keep_unsaved(self).await
    }

    /// Explicitly restores startup state and checks its pre-apply identity.
    ///
    /// # Errors
    /// Returns rollback, reconnect, or verification failures.
    // NOT cancel-safe: a transmitted rollback may reboot before cancellation.
    #[inline]
    pub async fn rollback(&mut self) -> Result<(), ApplyError> {
        finish::rollback(self).await
    }
}
