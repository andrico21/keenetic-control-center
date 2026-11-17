//! Follows the job events of the runner into `kcc_jobs`.

use alloc::{collections::BTreeMap, sync::Arc};

use kcc_app::jobs::{JobEvent, JobRunner, JobStatus};
use tokio::sync::broadcast::{Receiver, error::RecvError};

use super::SelfMetrics;

/// The job event subscription and the running jobs it has counted.
pub(super) struct JobFollower {
    /// The runner whose records settle a state after missed events.
    jobs: Arc<JobRunner>,
    /// Progress events of `jobs`.
    events: Receiver<JobEvent>,
    /// Running jobs counted in the gauge: id to (kind, state).
    known: BTreeMap<String, (String, String)>,
}

/// The `state` label of `status`.
fn state_label(status: JobStatus) -> Option<String> {
    let value = serde_json::to_value(status).ok()?;
    value.as_str().map(str::to_owned)
}

impl JobFollower {
    /// Subscribes to the events of `jobs`.
    pub(super) fn new(jobs: Arc<JobRunner>) -> Self {
        let events = jobs.subscribe();
        Self {
            jobs,
            events,
            known: BTreeMap::new(),
        }
    }

    /// Applies the next event to `metrics`; `false` once the runner is gone.
    ///
    /// After missed events every counted job is settled from its persisted record, so a
    /// lost terminal event cannot leave the running gauge raised.
    // cancel-safe: `recv` is cancel-safe and the metric update after it is synchronous.
    pub(super) async fn next(&mut self, metrics: &SelfMetrics) -> bool {
        match self.events.recv().await {
            Ok(event) => self.apply(metrics, &event),
            Err(RecvError::Lagged(_)) => self.settle_known(metrics),
            Err(RecvError::Closed) => return false,
        }
        true
    }

    /// Applies the state change of one event.
    fn apply(&mut self, metrics: &SelfMetrics, event: &JobEvent) {
        if let (Ok(record), Some(state)) = (self.jobs.get(&event.id), state_label(event.status)) {
            metrics.job_transition(&mut self.known, (record.id, record.kind), state);
        }
    }

    /// Re-reads every counted job and moves it to the state its record shows.
    fn settle_known(&mut self, metrics: &SelfMetrics) {
        let ids: Vec<String> = self.known.keys().cloned().collect();
        for id in ids {
            if let Ok(record) = self.jobs.get(&id)
                && let Some(state) = state_label(record.status)
            {
                metrics.job_transition(&mut self.known, (record.id, record.kind), state);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::{error::Error, time::Duration};

    use kcc_app::{
        audit::AuditLog,
        jobs::{JobRunner, JobStatus, JobTarget},
        persist::StateStore,
        registry::RouterRegistry,
        settings::OutboundConfig,
    };
    use tokio::{sync::oneshot, time::timeout};

    use super::{JobFollower, SelfMetrics};

    /// G-19: a receiver that lagged past a job's terminal event settles the counted jobs
    /// from their records, so the running gauge equals the jobs that really run.
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "the gauge values are the contract"
    )]
    #[tokio::test]
    async fn lagged_events_leave_the_running_gauge_exact() -> Result<(), Box<dyn Error>> {
        let temp = tempfile::TempDir::new()?;
        let state = StateStore::open(&temp.path().join("state"))?;
        let registry = Arc::new(RouterRegistry::new(
            state.clone(),
            &[],
            &OutboundConfig::default(),
        )?);
        let runner = JobRunner::open(state.clone(), registry, AuditLog::spawn(&state)?).await?;
        let metrics = SelfMetrics::new("test")?;
        let mut follower = JobFollower::new(Arc::clone(&runner));
        let mut observer = runner.subscribe();

        let (reported, report_seen) = oneshot::channel();
        let (finish_first, first_held) = oneshot::channel::<()>();
        drop(
            runner
                .start(
                    "first".to_owned(),
                    JobTarget::Read(None),
                    async move |context| {
                        context.progress(10);
                        let _reported: Result<(), ()> = reported.send(());
                        first_held.await.map_err(|error| error.to_string())
                    },
                )
                .await?,
        );
        report_seen.await?;
        assert!(follower.next(&metrics).await);
        let running = |kind: &str| -> Result<i64, Box<dyn Error>> {
            Ok(metrics
                .jobs
                .get_metric_with_label_values(&[kind, "running"])?
                .get())
        };
        assert_eq!(running("first")?, 1, "the first job runs");

        let _finished_first: Result<(), ()> = finish_first.send(());
        timeout(Duration::from_secs(5), async {
            loop {
                if observer.recv().await?.status == JobStatus::Completed {
                    return Ok::<(), Box<dyn Error>>(());
                }
            }
        })
        .await??;

        let (flooded, flood_seen) = oneshot::channel();
        let (finish_second, second_held) = oneshot::channel::<()>();
        drop(
            runner
                .start(
                    "second".to_owned(),
                    JobTarget::Read(None),
                    async move |context| {
                        for percent in 0..=200_u8 {
                            context.progress(percent);
                        }
                        let _flooded: Result<(), ()> = flooded.send(());
                        second_held.await.map_err(|error| error.to_string())
                    },
                )
                .await?,
        );
        flood_seen.await?;
        while !follower.events.is_empty() {
            assert!(follower.next(&metrics).await);
        }

        assert_eq!(running("first")?, 0, "the finished job no longer runs");
        assert_eq!(running("second")?, 1, "the second job runs");
        let _finished_second: Result<(), ()> = finish_second.send(());
        Ok(())
    }
}
