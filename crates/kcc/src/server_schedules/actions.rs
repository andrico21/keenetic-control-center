//! The four scheduled actions.
//!
//! Each runs as a background job of kind `scheduled.<action>` whose id the notifier leaves
//! to the scheduler, holding a workflow bracket guard while it changes the router.
//!
//! The preset action is not wired yet: a preset schedule that reaches a run ends it
//! skipped with `preset_unavailable`.

mod backup;
mod policy;
mod reboot;
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]
mod tests;

extern crate alloc;

use alloc::sync::Arc;
use core::{fmt::Debug, pin::Pin};

use kcc_app::{
    audit::{Actor, AuditLog},
    backups::BackupStore,
    jobs::{JobError, JobRunner, JobTarget},
    permissions::Role,
    registry::RouterRegistry,
    schedules::model::{Action, Schedule},
    workflow::{ChangeWorkflow, WorkflowError},
};
use kcc_migrate::{
    apply::{Clock as ApplyClock, SystemClock},
    presets::store::PresetStore,
};
use tokio::sync::oneshot;

use super::{Timings, notices::Notices};
use crate::server_services::Services;

/// How an action ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ActionResult {
    /// Done.
    Done {
        /// The router has changes it has not saved.
        unsaved: bool,
        /// The router's `show last-change` checksum after a change.
        checksum: Option<String>,
        /// The job that carried it out.
        job: Option<String>,
    },
    /// Failed with error code `code`.
    Failed {
        /// Machine-read error code.
        code: &'static str,
        /// The job that carried it out, when one started.
        job: Option<String>,
    },
    /// Not carried out, for `reason`.
    Skipped {
        /// Machine-read reason code.
        reason: &'static str,
        /// The job, when one started.
        job: Option<String>,
    },
    /// The router's lease or write-job slot is taken; nothing was sent.
    Busy,
}

impl ActionResult {
    /// The same result carrying job `id`.
    fn in_job(self, id: String) -> Self {
        match self {
            Self::Done {
                unsaved,
                checksum,
                job: _,
            } => Self::Done {
                unsaved,
                checksum,
                job: Some(id),
            },
            Self::Failed { code, job: _ } => Self::Failed {
                code,
                job: Some(id),
            },
            Self::Skipped { reason, job: _ } => Self::Skipped {
                reason,
                job: Some(id),
            },
            Self::Busy => Self::Busy,
        }
    }
}

/// One run's request to an action.
#[derive(Debug)]
pub(crate) struct Call<'call> {
    /// The schedule.
    schedule: &'call Schedule,
    /// The owner's role at run time.
    role: &'call Role,
    /// `system:schedule:<id>`.
    actor: Actor,
    /// The wall clock at the run's start, Unix seconds.
    now: i64,
}

impl<'call> Call<'call> {
    /// A request to run `schedule`'s action with `role` as `actor` at `now`.
    pub(crate) const fn new(
        schedule: &'call Schedule,
        role: &'call Role,
        actor: Actor,
        now: i64,
    ) -> Self {
        Self {
            schedule,
            role,
            actor,
            now,
        }
    }

    /// The schedule.
    #[cfg(test)]
    pub(crate) const fn schedule(&self) -> &Schedule {
        self.schedule
    }
}

/// A running action.
pub(crate) type Running<'call> = Pin<Box<dyn Future<Output = ActionResult> + Send + 'call>>;

/// Carries out scheduled actions.
pub(crate) trait Actions: Debug + Send + Sync {
    /// Runs `call`'s action once.
    fn start<'call>(&'call self, call: Call<'call>) -> Running<'call>;
}

/// What the actions use, so that `kcc serve` and a CLI run-now can each build one.
#[derive(Clone, Debug)]
pub(crate) struct ActionDeps {
    /// Router profiles and clients.
    registry: Arc<RouterRegistry>,
    /// The change workflow.
    workflow: Arc<ChangeWorkflow>,
    /// Background jobs.
    jobs: Arc<JobRunner>,
    /// Startup-configuration backups.
    backups: Arc<BackupStore>,
    /// The audit writer.
    #[expect(dead_code, reason = "the preset action audits through it")]
    audit: AuditLog,
    /// Stored presets.
    #[expect(dead_code, reason = "the preset action reads it")]
    presets: Arc<PresetStore>,
    /// The notifier, in `kcc serve`.
    notify: Option<Arc<dyn Notices>>,
    /// The preset applier's clock.
    #[expect(dead_code, reason = "the preset action runs the applier on it")]
    apply_clock: Arc<dyn ApplyClock>,
    /// Reboot waits.
    timings: Timings,
}

impl ActionDeps {
    /// The actions of `kcc serve` over `services`, reporting to `notify`.
    pub(crate) fn for_server(
        services: &Services,
        notify: Option<Arc<dyn Notices>>,
        timings: Timings,
    ) -> Self {
        Self {
            registry: Arc::clone(&services.registry),
            workflow: Arc::clone(&services.workflow),
            jobs: Arc::clone(&services.jobs),
            backups: Arc::clone(&services.backups),
            audit: services.audit.clone(),
            presets: Arc::new(PresetStore::new(
                services.state.clone(),
                services.key.duplicate(),
            )),
            notify,
            apply_clock: Arc::new(SystemClock::default()),
            timings,
        }
    }

    /// Runs `work` as a job of kind `scheduled.<kind>` on `target` and returns its result
    /// with the job's id, once the job ended and freed its router slot. The notifier
    /// leaves the job's failure to the scheduler.
    // NOT cancel-safe: dropped, the job runs on and its result is lost.
    async fn in_job<F, W>(&self, kind: &'static str, target: JobTarget, work: W) -> ActionResult
    where
        W: FnOnce() -> F + Send + 'static,
        F: Future<Output = ActionResult> + Send + 'static,
    {
        let (sender, receiver) = oneshot::channel();
        let started = self
            .jobs
            .start(format!("scheduled.{kind}"), target, async move |_context| {
                let result = work().await;
                let verdict = match &result {
                    ActionResult::Done {
                        unsaved: _,
                        checksum: _,
                        job: _,
                    }
                    | ActionResult::Skipped { reason: _, job: _ } => Ok(()),
                    ActionResult::Failed { code, job: _ } => Err((*code).to_owned()),
                    ActionResult::Busy => Err("router_busy".to_owned()),
                };
                drop(sender.send(result));
                verdict
            })
            .await;
        let id = match started {
            Ok(id) => id,
            Err(JobError::RouterBusy { router: _ }) => return ActionResult::Busy,
            Err(error) => {
                tracing::warn!(target: super::TARGET, %error, "a scheduled job did not start");
                return ActionResult::Failed {
                    code: "job_start",
                    job: None,
                };
            }
        };
        if let Some(notify) = &self.notify {
            notify.claim_job(id.clone());
        }
        let result = receiver.await.unwrap_or(ActionResult::Failed {
            code: "job_lost",
            job: None,
        });
        self.jobs.ended(&id).await;
        result.in_job(id)
    }
}

impl Actions for ActionDeps {
    fn start<'call>(&'call self, call: Call<'call>) -> Running<'call> {
        Box::pin(async move {
            match &call.schedule.action {
                Action::PolicySwitch { mac, policy } => {
                    policy::switch(self, &call, (mac.as_str(), policy.as_str())).await
                }
                Action::Backup => backup::store(self, &call).await,
                Action::Reboot => reboot::restart(self, &call).await,
                Action::Preset {
                    preset_id: _,
                    ack_documentation_tier: _,
                } => ActionResult::Skipped {
                    reason: "preset_unavailable",
                    job: None,
                },
                _ => ActionResult::Skipped {
                    reason: "unsupported",
                    job: None,
                },
            }
        })
    }
}

/// The result of a workflow error: busy, or failed `router`.
const fn failure(error: &WorkflowError) -> ActionResult {
    if matches!(error, WorkflowError::RouterBusy { actor: _ }) {
        ActionResult::Busy
    } else {
        failed("router")
    }
}

/// Failed with `code`.
const fn failed(code: &'static str) -> ActionResult {
    ActionResult::Failed { code, job: None }
}
