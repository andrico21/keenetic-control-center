//! A migration's apply while kcc runs it: the progress its job reports (kept so a page
//! that connects later replays it from the start), and the applier the job hands back,
//! which commits or rolls back.

use alloc::{collections::BTreeMap, sync::Arc};

use kcc_app::jobs::{JobEvent, JobProgress, JobStatus};
use kcc_migrate::apply::Applier;
use serde_json::Value;
use tokio::sync::{
    Mutex as AsyncMutex, MutexGuard as AsyncGuard,
    broadcast::{Receiver, error::RecvError},
    watch,
};

/// What the router answered to one setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// It took the setting.
    Applied,
    /// It refused the setting.
    Rejected,
    /// Its answer is unknown: the connection broke.
    Unknown,
}

impl Outcome {
    /// The outcome's name in data attributes.
    pub(crate) const fn slug(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Unknown => "unknown",
        }
    }
}

/// One setting the job sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sent {
    /// Its index in the planned source.
    index: usize,
    /// What the router answered.
    outcome: Outcome,
}

impl Sent {
    /// Its index in the planned source.
    pub(crate) const fn index(self) -> usize {
        self.index
    }

    /// What the router answered.
    pub(crate) const fn outcome(self) -> Outcome {
        self.outcome
    }
}

/// The apply's progress so far.
#[derive(Debug, Clone, Default)]
pub(crate) struct Progress {
    /// Percent done.
    percent: u8,
    /// Every setting sent, in order.
    sent: Vec<Sent>,
    /// Unix time kcc last worked on the router: the engine renews the fail-safe timer at
    /// least once a minute while it works and once more at its end.
    active_at: u64,
    /// The job's status once it ended.
    status: Option<JobStatus>,
    /// Whether the follower copied every event of the job.
    followed: bool,
    /// Whether the end is recorded and the applier (if any) handed back.
    settled: bool,
}

impl Progress {
    /// Percent done.
    pub(crate) const fn percent(&self) -> u8 {
        self.percent
    }

    /// Every setting sent, in order.
    pub(crate) fn sent(&self) -> &[Sent] {
        &self.sent
    }

    /// Unix time kcc last worked on the router.
    pub(crate) const fn active_at(&self) -> u64 {
        self.active_at
    }

    /// Whether every event is copied and the end recorded: nothing more will come.
    pub(crate) const fn finished(&self) -> bool {
        self.followed && self.settled
    }

    /// Whether the job still runs.
    pub(crate) const fn running(&self) -> bool {
        self.status.is_none()
    }
}

/// One running or finished apply.
pub(crate) struct Live {
    /// The progress, written by the follower and the settler.
    progress: watch::Sender<Progress>,
    /// The applier, once the job handed it back; taken by commit or rollback.
    applier: AsyncMutex<Option<Applier>>,
    /// For each planned setting, its source line and redacted text.
    texts: BTreeMap<usize, (usize, String)>,
}

impl Live {
    /// An apply started at `started_at` sending the settings of `texts`.
    pub(crate) fn new(started_at: u64, texts: BTreeMap<usize, (usize, String)>) -> Arc<Self> {
        let (progress, _receiver) = watch::channel(Progress {
            active_at: started_at,
            ..Progress::default()
        });
        Arc::new(Self {
            progress,
            applier: AsyncMutex::new(None),
            texts,
        })
    }

    /// The progress, from the start.
    pub(crate) fn watch(&self) -> watch::Receiver<Progress> {
        self.progress.subscribe()
    }

    /// The source line and redacted text of planned setting `index`.
    pub(crate) fn text(&self, index: usize) -> Option<&(usize, String)> {
        self.texts.get(&index)
    }

    /// The applier slot.
    // cancel-safe: it only waits for the lock.
    pub(crate) async fn applier(&self) -> AsyncGuard<'_, Option<Applier>> {
        self.applier.lock().await
    }

    /// Hands back `applier` and marks the end, at unix time `at`, recorded.
    // NOT cancel-safe: dropped while waiting for the lock, the applier passed in is dropped with
    // the future instead of being stored.
    pub(crate) async fn settle(&self, applier: Option<Applier>, at: u64) {
        *self.applier.lock().await = applier;
        self.progress.send_modify(|progress| {
            progress.settled = true;
            progress.active_at = at;
        });
    }

    /// Copies the progress of job `id` from `events`, a subscription taken before the job
    /// started, until it ends; `now` tells the time.
    // cancel-safe: only local state changes.
    pub(crate) async fn follow<C>(&self, mut events: Receiver<JobEvent>, id: &str, now: C)
    where
        C: Fn() -> u64,
    {
        loop {
            match events.recv().await {
                Ok(event) if event.id == id => {
                    let ended = event.status != JobStatus::Running;
                    self.progress.send_modify(|progress| {
                        progress.percent = progress.percent.max(event.progress);
                        if let Some(JobProgress::Structured(value)) = &event.detail
                            && let Some(sent) = sent(value)
                        {
                            progress.sent.push(sent);
                            progress.active_at = now();
                        }
                        if ended {
                            progress.status = Some(event.status);
                            progress.followed = true;
                        }
                    });
                    if ended {
                        return;
                    }
                }
                Ok(_) => {}
                Err(RecvError::Lagged(missed)) => {
                    tracing::warn!(missed, job = id, "migration progress lagged");
                }
                Err(RecvError::Closed) => {
                    self.progress
                        .send_modify(|progress| progress.followed = true);
                    return;
                }
            }
        }
    }
}

/// The setting a structured progress event reports.
fn sent(value: &Value) -> Option<Sent> {
    let index = usize::try_from(value.get("source_index")?.as_u64()?).ok()?;
    let answer = value
        .get("outcome")
        .or_else(|| value.pointer("/outcomes/0"))?
        .as_str()?;
    let outcome = match answer {
        "Applied" => Outcome::Applied,
        "Rejected" => Outcome::Rejected,
        _ => Outcome::Unknown,
    };
    Some(Sent { index, outcome })
}
