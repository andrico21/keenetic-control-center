//! Failed background jobs. A failure is reported once the merge window after it ends, so
//! that the scheduler, which reports its own runs, can claim the job id first.

extern crate alloc;

use alloc::{collections::VecDeque, sync::Arc};
use core::future::pending;
use std::sync::{Mutex, PoisonError};

use kcc_app::{jobs::JobStatus, notify_store::NotifyEvent};
use tokio::{
    sync::broadcast::error::RecvError,
    task::spawn_blocking,
    time::{Instant, sleep_until},
};

use super::{Shared, render};

/// Failed jobs waiting for their window, and job ids the scheduler registered; beyond
/// this the oldest is dropped.
const MAX_WAITING: usize = 256;

/// The ids of jobs the scheduler started; their failures are its to report.
#[derive(Clone, Debug, Default)]
pub(crate) struct ScheduledJobs {
    /// Registered ids, oldest first.
    ids: Arc<Mutex<VecDeque<String>>>,
}

impl ScheduledJobs {
    /// Registers a job the scheduler started.
    #[expect(dead_code, reason = "the scheduler registers the jobs it starts")]
    pub(crate) fn register(&self, id: String) {
        let mut ids = self.ids.lock().unwrap_or_else(PoisonError::into_inner);
        if ids.len() >= MAX_WAITING {
            drop(ids.pop_front());
        }
        ids.push_back(id);
    }

    /// Whether `id` was registered; forgets it.
    fn take(&self, id: &str) -> bool {
        let mut ids = self.ids.lock().unwrap_or_else(PoisonError::into_inner);
        let removed = ids
            .iter()
            .position(|known| known == id)
            .and_then(|index| ids.remove(index));
        drop(ids);
        removed.is_some()
    }
}

/// Sleeps until `wake`; never resolves without one.
// cancel-safe: a timer.
async fn sleep_until_some(wake: Option<Instant>) {
    match wake {
        Some(at) => sleep_until(at).await,
        None => pending().await,
    }
}

/// Follows the job runner's events until it is dropped.
// cancel-safe: a failure not yet resolved is only lost, never reported twice.
pub(super) async fn follow(shared: Arc<Shared>) {
    let mut events = shared.deps.jobs.subscribe();
    let mut waiting: VecDeque<(Instant, String)> = VecDeque::new();
    loop {
        let next = waiting.front().map(|&(at, _)| at);
        tokio::select! {
            biased;
            () = sleep_until_some(next) => {
                if let Some((_at, id)) = waiting.pop_front() {
                    resolve(&shared, id).await;
                }
            }
            received = events.recv() => match received {
                Ok(event) => {
                    if event.status == JobStatus::Failed
                        && !waiting.iter().any(|(_at, id)| *id == event.id)
                    {
                        if waiting.len() >= MAX_WAITING {
                            drop(waiting.pop_front());
                        }
                        let now = Instant::now();
                        let at = now.checked_add(shared.timings.merge_window).unwrap_or(now);
                        waiting.push_back((at, event.id));
                    }
                }
                Err(RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "notifier fell behind the job events; events skipped");
                }
                Err(RecvError::Closed) => return,
            },
        }
    }
}

/// Reports the failed job `id` unless the scheduler claimed it.
// cancel-safe: reads only; a dropped read sends nothing.
async fn resolve(shared: &Shared, id: String) {
    if shared.scheduled.take(&id) || !shared.wants(NotifyEvent::JobFailed) {
        return;
    }
    let jobs = Arc::clone(&shared.deps.jobs);
    match spawn_blocking(move || jobs.get(&id)).await {
        Ok(Ok(record)) => shared.emit(NotifyEvent::JobFailed, |locale| {
            render::job_failed(locale, &record.kind, record.router.as_deref())
        }),
        Ok(Err(error)) => {
            tracing::warn!(%error, "a failed job cannot be read for its notification");
        }
        Err(error) => {
            tracing::warn!(%error, "a failed job read did not finish");
        }
    }
}
