//! The progress of the jobs the system pages start.
//!
//! The job runner broadcasts progress to whoever listens at that moment; a browser that
//! opens the job's stream a moment later would miss the start. Every detail a followed
//! job reports is therefore kept here, in a watch channel per job, until the job ends, so
//! a stream always starts from the beginning.

use alloc::{collections::VecDeque, sync::Arc};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kcc_app::jobs::{JobEvent, JobProgress, JobRunner, JobStatus};
use tokio::sync::{
    broadcast::{Receiver, error::RecvError},
    watch,
};

/// Jobs whose progress is kept; the oldest is forgotten first.
const KEPT_JOBS: usize = 32;

/// Details kept per job; a longer output keeps its beginning.
const KEPT_DETAILS: usize = 500;

/// What a job showed so far.
#[derive(Debug, Clone)]
pub(crate) struct JobView {
    /// Its status.
    status: JobStatus,
    /// Every detail it reported, in order.
    details: Vec<JobProgress>,
}

impl JobView {
    /// Its status.
    pub(crate) const fn status(&self) -> JobStatus {
        self.status
    }

    /// Every detail it reported, in order.
    pub(crate) fn details(&self) -> &[JobProgress] {
        &self.details
    }
}

/// The kept progress of recent jobs, by id.
pub(crate) struct JobFeeds {
    /// Job id and its progress, oldest first.
    feeds: Mutex<VecDeque<(String, watch::Receiver<JobView>)>>,
}

impl JobFeeds {
    /// No job followed yet.
    pub(crate) const fn new() -> Self {
        Self {
            feeds: Mutex::new(VecDeque::new()),
        }
    }

    /// Keeps the progress of job `id` of `jobs` from `events`, a subscription taken before
    /// the job started, until the job ends.
    pub(crate) fn follow(&self, jobs: Arc<JobRunner>, events: Receiver<JobEvent>, id: String) {
        let (sender, receiver) = watch::channel(JobView {
            status: JobStatus::Running,
            details: Vec::new(),
        });
        let mut feeds = lock(&self.feeds);
        if feeds.len() >= KEPT_JOBS {
            drop(feeds.pop_front());
        }
        feeds.push_back((id.clone(), receiver));
        drop(feeds);
        drop(tokio::spawn(collect(jobs, events, id, sender)));
    }

    /// The progress of job `id`, when it is kept.
    pub(crate) fn get(&self, id: &str) -> Option<watch::Receiver<JobView>> {
        lock(&self.feeds)
            .iter()
            .find(|(job, _)| job == id)
            .map(|(_, feed)| feed.clone())
    }
}

/// Copies the progress of job `id` from `events` into `sender` until the job ends.
// cancel-safe: only local state changes.
async fn collect(
    jobs: Arc<JobRunner>,
    mut events: Receiver<JobEvent>,
    id: String,
    sender: watch::Sender<JobView>,
) {
    loop {
        match events.recv().await {
            Ok(event) if event.id == id => {
                let ended = event.status != JobStatus::Running;
                sender.send_modify(|view| {
                    view.status = event.status;
                    if let Some(detail) = event.detail
                        && view.details.len() < KEPT_DETAILS
                    {
                        view.details.push(detail);
                    }
                });
                if ended {
                    return;
                }
            }
            Ok(_) => {}
            Err(RecvError::Lagged(missed)) => {
                tracing::warn!(missed, job = id, "job progress lagged");
                if let Ok(record) = jobs.get(&id)
                    && record.status != JobStatus::Running
                {
                    sender.send_modify(|view| view.status = record.status);
                    return;
                }
            }
            Err(RecvError::Closed) => return,
        }
    }
}

/// The kept feeds; a panic while holding the lock cannot leave an entry half-written, so
/// a poisoned lock is used as is.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
