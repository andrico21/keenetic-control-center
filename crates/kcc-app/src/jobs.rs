//! Persisted cancellable long-running jobs.
#![expect(
    clippy::absolute_paths,
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    clippy::shadow_unrelated,
    clippy::std_instead_of_core,
    clippy::renamed_function_params,
    reason = "job orchestration prioritizes lifecycle clarity; public async bodies are not useful inline candidates"
)]

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{fmt, time::Duration};
use std::{
    fs, io,
    path::PathBuf,
    sync::atomic::{AtomicU8, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    sync::{Mutex, Notify, broadcast},
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    accounts::{Clock, SystemClock},
    persist::{StateError, StateStore, create_private_dir, io_error, write_atomic},
    registry::{RegistryError, RouterRegistry},
};

/// Default age bound for finished job records: 30 days.
pub const DEFAULT_FINISHED_RETENTION: Duration = Duration::from_hours(30 * 24);

mod job_ownership;

use job_ownership::JobOwnership;

/// Job lifecycle status persisted on disk.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JobStatus {
    /// Currently executing.
    Running,
    /// Completed successfully.
    Completed,
    /// Failed.
    Failed,
    /// Cancelled by the caller.
    Cancelled,
    /// Was running when the previous process exited.
    Interrupted,
}

/// Persisted job metadata.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct JobRecord {
    /// Stable job id.
    pub id: String,
    /// Stable job kind.
    pub kind: String,
    /// Target router, when applicable.
    pub router: Option<String>,
    /// Whether this job mutates router state.
    pub write: bool,
    /// Lifecycle status.
    pub status: JobStatus,
    /// Latest progress percentage.
    pub progress: u8,
    /// Unix creation timestamp.
    pub created_at: u64,
    /// Unix update timestamp.
    pub updated_at: u64,
    /// Optional stable failure message.
    pub message: Option<String>,
}

/// Progress event broadcast to interested front-ends.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum JobProgress {
    /// One textual output line from a streaming operation.
    OutputLine(String),
    /// Operation-specific structured progress data.
    Structured(Value),
}

/// Progress event broadcast to interested front-ends.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct JobEvent {
    /// Job id.
    pub id: String,
    /// Progress percentage.
    pub progress: u8,
    /// Current status.
    pub status: JobStatus,
    /// Optional operation-specific progress payload.
    pub detail: Option<JobProgress>,
}

/// Recovery state discovered for an interrupted router job.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct RecoveryNotice {
    /// Interrupted job id.
    pub job_id: String,
    /// Router id.
    pub router: String,
    /// Raw fail-safe object from `show last-change`.
    pub fail_safe: Value,
    /// Whether the router reports a scheduled reboot.
    pub scheduled_reboot: bool,
}

/// Outcome of cancelling and draining active jobs during graceful shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DrainReport {
    /// Jobs that were active and received cancellation.
    pub cancelled: usize,
    /// Jobs still running when the caller-supplied timeout elapsed.
    pub still_running: usize,
}

/// Job runner failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JobError {
    /// Another write job is already running on the router.
    #[error("router busy: {router}")]
    RouterBusy {
        /// Router id.
        router: String,
    },
    /// The job id does not exist.
    #[error("job {id} was not found")]
    NotFound {
        /// Job id.
        id: String,
    },
    /// State storage failed.
    #[error(transparent)]
    State(#[from] StateError),
    /// Router recovery inspection failed.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// A persisted job is malformed.
    #[error("job state {path} is malformed")]
    Malformed {
        /// Invalid state path.
        path: PathBuf,
    },
}

/// Context passed to a running job body.
#[derive(Clone)]
pub struct JobContext {
    /// Job id.
    id: String,
    /// Cancellation token.
    cancellation: CancellationToken,
    /// Progress channel.
    events: broadcast::Sender<JobEvent>,
    /// Latest percentage paired with structured events.
    progress: Arc<AtomicU8>,
}

impl fmt::Debug for JobContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobContext")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl JobContext {
    /// Returns the cancellation token observed by the job body.
    #[inline]
    #[must_use]
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Broadcasts a progress update.
    #[inline]
    pub fn progress(&self, progress: u8) {
        let bounded = progress.min(100);
        self.progress.store(bounded, Ordering::Relaxed);
        drop(self.events.send(JobEvent {
            id: self.id.clone(),
            progress: bounded,
            status: JobStatus::Running,
            detail: None,
        }));
    }

    /// Broadcasts operation-specific progress while preserving the latest percentage.
    #[inline]
    pub fn structured_progress(&self, detail: JobProgress) {
        drop(self.events.send(JobEvent {
            id: self.id.clone(),
            progress: self.progress.load(Ordering::Relaxed),
            status: JobStatus::Running,
            detail: Some(detail),
        }));
    }
}

/// Persisted job orchestration service.
pub struct JobRunner {
    /// State store.
    state: StateStore,
    /// Router registry used for recovery inspection.
    registry: Arc<RouterRegistry>,
    /// Active cancellation tokens.
    active: Mutex<BTreeMap<String, CancellationToken>>,
    /// Router to active write-job id.
    write_jobs: Mutex<BTreeMap<String, String>>,
    /// Progress broadcast.
    events: broadcast::Sender<JobEvent>,
    /// Recovery notices discovered on startup.
    recovery: Mutex<Vec<RecoveryNotice>>,
    /// Signals that an active job task reached its terminal cleanup.
    finished: Notify,
    /// Cross-process ownership of running jobs.
    ownership: JobOwnership,
    /// Timestamp source shared by lifecycle updates and pruning.
    clock: Arc<dyn Clock>,
    /// Maximum age of terminal job records.
    finished_retention: Duration,
}

impl fmt::Debug for JobRunner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobRunner")
            .field("state", &self.state)
            .field("registry", &self.registry)
            .finish_non_exhaustive()
    }
}

impl JobRunner {
    /// Creates a runner and marks stale running jobs interrupted.
    ///
    /// # Errors
    ///
    /// Returns state, parse, or router inspection errors.
    // cancel-safe: startup recovery performs only reads and atomic local state writes.
    pub async fn open(
        state: StateStore,
        registry: Arc<RouterRegistry>,
    ) -> Result<Arc<Self>, JobError> {
        Self::open_with_retention(
            state,
            registry,
            DEFAULT_FINISHED_RETENTION,
            Arc::new(SystemClock),
        )
        .await
    }

    /// Creates a runner with explicit finished-record retention and time source.
    ///
    /// # Errors
    ///
    /// Returns state, parse, or router inspection errors.
    // cancel-safe: startup recovery performs only reads and atomic local state writes.
    pub async fn open_with_retention(
        state: StateStore,
        registry: Arc<RouterRegistry>,
        finished_retention: Duration,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, JobError> {
        let (events, _receiver) = broadcast::channel(128);
        let ownership = JobOwnership::new(state.clone());
        let runner = Arc::new(Self {
            state,
            registry,
            active: Mutex::new(BTreeMap::new()),
            write_jobs: Mutex::new(BTreeMap::new()),
            events,
            recovery: Mutex::new(Vec::new()),
            finished: Notify::new(),
            ownership,
            clock,
            finished_retention,
        });
        runner.prune_finished()?;
        runner.recover().await?;
        Ok(runner)
    }

    /// Subscribes to progress events.
    #[inline]
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<JobEvent> {
        self.events.subscribe()
    }

    /// Returns startup recovery notices.
    // cancel-safe: clones the notices under a lock; cancellation changes nothing.
    pub async fn recovery_notices(&self) -> Vec<RecoveryNotice> {
        self.recovery.lock().await.clone()
    }

    /// Gets one persisted job.
    ///
    /// # Errors
    ///
    /// Returns missing, malformed, or state I/O errors.
    pub fn get(&self, id: &str) -> Result<JobRecord, JobError> {
        let path = self.job_path(id)?;
        read_job(&path)?.ok_or_else(|| JobError::NotFound { id: id.to_owned() })
    }

    /// Cancels a running job.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::NotFound`] when the job is not active.
    // cancel-safe: the token is cancelled synchronously after the lock; cancelled earlier,
    // the job keeps running.
    pub async fn cancel(&self, id: &str) -> Result<(), JobError> {
        let token = self
            .active
            .lock()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| JobError::NotFound { id: id.to_owned() })?;
        token.cancel();
        Ok(())
    }

    /// Cancels every active job and waits up to `timeout` for task cleanup.
    ///
    /// This does not commit or roll back router state. A fail-safe armed by a
    /// running migration therefore remains armed for the router to resolve.
    // cancel-safe: cancellation leaves already-cancelled jobs running toward their ordinary cleanup.
    pub async fn drain(&self, timeout: Duration) -> DrainReport {
        let cancelled = {
            let active = self.active.lock().await;
            for token in active.values() {
                token.cancel();
            }
            active.len()
        };
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        loop {
            let finished = self.finished.notified();
            tokio::pin!(finished);
            let _: bool = finished.as_mut().enable();
            let still_running = self.active.lock().await.len();
            if still_running == 0 {
                return DrainReport {
                    cancelled,
                    still_running,
                };
            }
            if timeout_at(deadline, finished).await.is_err() {
                return DrainReport {
                    cancelled,
                    still_running: self.active.lock().await.len(),
                };
            }
        }
    }

    /// Starts a persisted job and returns its id immediately.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::RouterBusy`] for a second simultaneous write job on one router,
    /// or state I/O errors while persisting the initial record.
    // cancel-safe: ownership and map reservations roll back on every drop before the task is spawned.
    pub async fn start<F, Fut>(
        self: &Arc<Self>,
        kind: String,
        router: Option<String>,
        write: bool,
        work: F,
    ) -> Result<String, JobError>
    where
        F: FnOnce(JobContext) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let id = new_id();
        let cancellation = CancellationToken::new();
        let mut active = self.active.lock().await;
        let mut write_jobs = self.write_jobs.lock().await;
        if write {
            let target = router.as_ref().ok_or_else(|| JobError::RouterBusy {
                router: "missing".to_owned(),
            })?;
            if write_jobs.contains_key(target) {
                return Err(JobError::RouterBusy {
                    router: target.clone(),
                });
            }
        }
        let ownership = self.ownership.claim(&id)?;
        if let Some(target) = router.as_ref().filter(|_target| write) {
            drop(write_jobs.insert(target.clone(), id.clone()));
        }
        drop(active.insert(id.clone(), cancellation.clone()));
        let now = self.clock.unix_seconds();
        if let Err(error) = self.persist(&JobRecord {
            id: id.clone(),
            kind,
            router: router.clone(),
            write,
            status: JobStatus::Running,
            progress: 0,
            created_at: now,
            updated_at: now,
            message: None,
        }) {
            drop(active.remove(&id));
            if write && let Some(target) = &router {
                drop(write_jobs.remove(target));
            }
            return Err(error);
        }
        let owner = Arc::clone(self);
        let task_id = id.clone();
        let task_router = router.clone();
        let context = JobContext {
            id: task_id.clone(),
            cancellation: cancellation.clone(),
            events: owner.events.clone(),
            progress: Arc::new(AtomicU8::new(0)),
        };
        let terminal_progress = Arc::clone(&context.progress);
        let worker = tokio::spawn(async move { work(context).await });
        drop(tokio::spawn(async move {
            let (result, panicked) = match worker.await {
                Ok(result) => (result, false),
                Err(error) if error.is_panic() => (Err("job panicked".to_owned()), true),
                Err(_error) => (Err("job task was cancelled".to_owned()), false),
            };
            let status = match (result.is_ok(), cancellation.is_cancelled(), panicked) {
                (_, _, true) | (false, false, false) => JobStatus::Failed,
                (_, true, false) => JobStatus::Cancelled,
                (true, false, false) => JobStatus::Completed,
            };
            if let Ok(mut record) = owner.get(&task_id) {
                record.status = status;
                record.progress = if status == JobStatus::Completed {
                    100
                } else {
                    record.progress
                };
                record.updated_at = owner.clock.unix_seconds();
                record.message = result.err();
                drop(owner.persist(&record));
                drop(owner.events.send(JobEvent {
                    id: task_id.clone(),
                    progress: record.progress,
                    status,
                    detail: None,
                }));
            } else {
                tracing::warn!("job record unavailable at completion");
                drop(owner.events.send(JobEvent {
                    id: task_id.clone(),
                    progress: terminal_progress.load(Ordering::Relaxed),
                    status,
                    detail: None,
                }));
            }
            if write && let Some(target) = task_router {
                drop(owner.write_jobs.lock().await.remove(&target));
            }
            drop(owner.active.lock().await.remove(&task_id));
            owner.ownership.release(&task_id);
            owner.finished.notify_waiters();
        }));
        ownership.transfer();
        drop(write_jobs);
        drop(active);
        Ok(id)
    }

    /// Recovers running records and inspects affected routers for pending safety state.
    async fn recover(&self) -> Result<(), JobError> {
        for path in self.job_paths()? {
            let Some(mut record) = read_job(&path)? else {
                continue;
            };
            if record.status != JobStatus::Running {
                continue;
            }
            if self.ownership.is_held(&record.id)? {
                continue;
            }
            record.status = JobStatus::Interrupted;
            record.updated_at = self.clock.unix_seconds();
            self.persist(&record)?;
            if let Some(router) = record.router {
                let client = self.registry.client(&router).await?;
                let path =
                    kcc_rci::RciPath::from_segments(["show", "last-change"]).map_err(|_error| {
                        RegistryError::InvalidProfile {
                            reason: "last-change path".to_owned(),
                        }
                    })?;
                if let Ok(kcc_rci::RciBody::Json(response)) = client.show(&path, &()).await {
                    let fail_safe = response
                        .value
                        .get("fail-safe")
                        .cloned()
                        .unwrap_or(Value::Null);
                    let scheduled_reboot = response
                        .value
                        .pointer("/reboot/scheduled")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if fail_safe
                        .get("active")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                        || scheduled_reboot
                    {
                        self.recovery.lock().await.push(RecoveryNotice {
                            job_id: record.id,
                            router,
                            fail_safe,
                            scheduled_reboot,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Persists one job atomically.
    fn persist(&self, record: &JobRecord) -> Result<(), JobError> {
        let directory = self.jobs_dir()?;
        let _lock = self.state.lock(&format!("job-{}", record.id))?;
        let mut bytes =
            serde_json::to_vec_pretty(record).map_err(|_error| JobError::Malformed {
                path: directory.join(format!("{}.json", record.id)),
            })?;
        bytes.push(b'\n');
        write_atomic(&directory, &format!("{}.json", record.id), &bytes)?;
        Ok(())
    }

    /// Returns the private jobs directory.
    fn jobs_dir(&self) -> Result<PathBuf, JobError> {
        let directory = self.state.dir().join("jobs");
        create_private_dir(&directory)?;
        Ok(directory)
    }

    /// Returns one validated job path.
    fn job_path(&self, id: &str) -> Result<PathBuf, JobError> {
        validate_id(id)?;
        Ok(self.jobs_dir()?.join(format!("{id}.json")))
    }

    /// Lists persisted job paths.
    fn job_paths(&self) -> Result<Vec<PathBuf>, JobError> {
        let directory = self.jobs_dir()?;
        let mut paths = Vec::new();
        for listed in fs::read_dir(&directory).map_err(|error| io_error(&directory, error))? {
            let entry = listed.map_err(|error| io_error(&directory, error))?;
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                paths.push(entry.path());
            }
        }
        Ok(paths)
    }

    /// Removes terminal records older than the configured bound.
    fn prune_finished(&self) -> Result<(), JobError> {
        let retention = self.finished_retention.as_secs();
        if retention == 0 {
            return Ok(());
        }
        let cutoff = self.clock.unix_seconds().saturating_sub(retention);
        for path in self.job_paths()? {
            let Some(record) = read_job(&path)? else {
                continue;
            };
            if record.status != JobStatus::Running && record.updated_at < cutoff {
                fs::remove_file(&path).map_err(|error| io_error(&path, error))?;
            }
        }
        Ok(())
    }
}

/// Reads one persisted job if present.
fn read_job(path: &PathBuf) -> Result<Option<JobRecord>, JobError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(path, error).into()),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_error| JobError::Malformed { path: path.clone() })
}

/// Validates a job id as one safe path component.
fn validate_id(id: &str) -> Result<(), JobError> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(JobError::NotFound { id: id.to_owned() });
    }
    Ok(())
}

/// Allocates a process-unique sortable job id.
fn new_id() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    format!("job-{timestamp}-{sequence}")
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::{
        future::pending,
        task::{Context, Poll, Waker},
        time::Duration,
    };
    use std::fs;

    use tokio::{sync::oneshot, time::timeout};

    use super::{JobRunner, JobStatus};
    use crate::{persist::StateStore, registry::RouterRegistry, settings::OutboundConfig};

    #[expect(
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "the assertion proves the start future reached the held active lock"
    )]
    #[tokio::test]
    async fn cancelled_start_releases_router_write_slot() -> Result<(), Box<dyn core::error::Error>>
    {
        let temp = tempfile::TempDir::new()?;
        let state = StateStore::open(&temp.path().join("state"))?;
        let registry = Arc::new(RouterRegistry::new(
            state.clone(),
            &[],
            &OutboundConfig::default(),
        )?);
        let runner = JobRunner::open(state, registry).await?;
        {
            let active = runner.active.lock().await;
            let start = runner.start(
                "cancelled".to_owned(),
                Some("router".to_owned()),
                true,
                async |_context| pending::<Result<(), String>>().await,
            );
            tokio::pin!(start);
            let mut context = Context::from_waker(Waker::noop());
            assert!(matches!(start.as_mut().poll(&mut context), Poll::Pending));
            drop(active);
        }

        drop(
            runner
                .start(
                    "retry".to_owned(),
                    Some("router".to_owned()),
                    true,
                    async |_context| Ok(()),
                )
                .await?,
        );
        Ok(())
    }

    #[expect(
        clippy::panic,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "the job panic is the behavior under test"
    )]
    #[tokio::test]
    async fn panicking_job_fails_record_and_releases_router_write_slot()
    -> Result<(), Box<dyn core::error::Error>> {
        struct PanicStarted(Option<oneshot::Sender<()>>);

        impl Drop for PanicStarted {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _delivered: Result<(), ()> = sender.send(());
                }
            }
        }

        let temp = tempfile::TempDir::new()?;
        let state = StateStore::open(&temp.path().join("state"))?;
        let registry = Arc::new(RouterRegistry::new(
            state.clone(),
            &[],
            &OutboundConfig::default(),
        )?);
        let runner = JobRunner::open(state, registry).await?;
        let mut events = runner.subscribe();
        let finished = runner.finished.notified();
        tokio::pin!(finished);
        let _: bool = finished.as_mut().enable();
        let (panic_started, panic_observed) = oneshot::channel();
        let id = runner
            .start(
                "panic".to_owned(),
                Some("router".to_owned()),
                true,
                async move |_context| {
                    let _signal = PanicStarted(Some(panic_started));
                    panic!("synthetic job panic");
                    #[expect(unreachable_code, reason = "the future output type follows the panic")]
                    Ok(())
                },
            )
            .await?;
        panic_observed.await?;
        let terminal = timeout(Duration::from_secs(1), events.recv()).await??;
        timeout(Duration::from_secs(1), finished).await?;

        assert_eq!(terminal.id, id);
        assert_eq!(terminal.status, JobStatus::Failed);
        assert_eq!(runner.get(&id)?.status, JobStatus::Failed);
        drop(
            runner
                .start(
                    "retry".to_owned(),
                    Some("router".to_owned()),
                    true,
                    async |_context| Ok(()),
                )
                .await?,
        );
        Ok(())
    }

    #[expect(
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "the assertions prove cleanup survives a missing persisted record"
    )]
    #[tokio::test]
    async fn missing_record_still_emits_terminal_event_and_releases_router_write_slot()
    -> Result<(), Box<dyn core::error::Error>> {
        let temp = tempfile::TempDir::new()?;
        let state = StateStore::open(&temp.path().join("state"))?;
        let registry = Arc::new(RouterRegistry::new(
            state.clone(),
            &[],
            &OutboundConfig::default(),
        )?);
        let runner = JobRunner::open(state.clone(), registry).await?;
        let mut events = runner.subscribe();
        let finished = runner.finished.notified();
        tokio::pin!(finished);
        let _: bool = finished.as_mut().enable();
        let (release, held) = oneshot::channel();
        let id = runner
            .start(
                "missing-record".to_owned(),
                Some("router".to_owned()),
                true,
                async move |_context| held.await.map_err(|error| error.to_string()),
            )
            .await?;
        fs::remove_file(state.dir().join("jobs").join(format!("{id}.json")))?;

        release.send(()).map_err(|()| "job receiver dropped")?;
        let terminal = timeout(Duration::from_secs(1), events.recv()).await??;
        timeout(Duration::from_secs(1), finished).await?;

        assert_eq!(terminal.id, id);
        assert_eq!(terminal.status, JobStatus::Completed);
        drop(
            runner
                .start(
                    "retry".to_owned(),
                    Some("router".to_owned()),
                    true,
                    async |_context| Ok(()),
                )
                .await?,
        );
        Ok(())
    }
}
