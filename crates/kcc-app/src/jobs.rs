//! Persisted cancellable long-running jobs.
#![expect(
    clippy::absolute_paths,
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
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
    audit::{Actor, ActorKind, AuditEvent, AuditLog},
    persist::{StateError, StateStore, create_private_dir, io_error, write_atomic},
    registry::{RegistryError, RouterRegistry},
};

/// Longest wait for one router's `show last-change` during startup recovery.
const RECOVERY_PROBE_BOUND: Duration = Duration::from_secs(5);

/// Default age bound for finished job records: 30 days.
pub const DEFAULT_FINISHED_RETENTION: Duration = Duration::from_hours(30 * 24);

mod job_id;
mod job_ownership;

use job_id::JobIdAllocator;
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
    /// A generated identifier could not be claimed in the shared state directory.
    #[error("job could not be started; retry")]
    IdCollision,
    /// The operating system could not supply identifier entropy.
    #[error("job identifier could not be allocated")]
    IdUnavailable,
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
    /// Signals that an active job task reached its terminal cleanup.
    finished: Notify,
    /// Cross-process ownership of running jobs.
    ownership: JobOwnership,
    /// Timestamp source shared by lifecycle updates and pruning.
    clock: Arc<dyn Clock>,
    /// Maximum age of terminal job records.
    finished_retention: Duration,
    /// Cross-process-safe identifier allocator.
    ids: JobIdAllocator,
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
    /// Returns state or parse errors.
    // cancel-safe: startup recovery performs only reads and atomic local state writes.
    pub async fn open(
        state: StateStore,
        registry: Arc<RouterRegistry>,
        audit: AuditLog,
    ) -> Result<Arc<Self>, JobError> {
        Self::open_with_retention(
            state,
            registry,
            audit,
            DEFAULT_FINISHED_RETENTION,
            Arc::new(SystemClock),
        )
        .await
    }

    /// Creates a runner with explicit finished-record retention and time source.
    ///
    /// # Errors
    ///
    /// Returns state or parse errors.
    // cancel-safe: startup recovery performs only reads and atomic local state writes.
    pub async fn open_with_retention(
        state: StateStore,
        registry: Arc<RouterRegistry>,
        audit: AuditLog,
        finished_retention: Duration,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, JobError> {
        let ids = JobIdAllocator::system();
        Self::open_with_ids(state, registry, audit, finished_retention, clock, ids).await
    }

    /// Creates a runner around one already initialized identifier allocator.
    // cancel-safe: startup recovery performs only reads and atomic local state writes.
    async fn open_with_ids(
        state: StateStore,
        registry: Arc<RouterRegistry>,
        audit: AuditLog,
        finished_retention: Duration,
        clock: Arc<dyn Clock>,
        ids: JobIdAllocator,
    ) -> Result<Arc<Self>, JobError> {
        let (events, _receiver) = broadcast::channel(128);
        let ownership = JobOwnership::new(state.clone());
        let runner = Arc::new(Self {
            state,
            registry,
            active: Mutex::new(BTreeMap::new()),
            write_jobs: Mutex::new(BTreeMap::new()),
            events,
            finished: Notify::new(),
            ownership,
            clock,
            finished_retention,
            ids,
        });
        runner.prune_finished()?;
        runner.recover(&audit).await?;
        Ok(runner)
    }

    /// Subscribes to progress events.
    #[inline]
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<JobEvent> {
        self.events.subscribe()
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
    /// [`JobError::IdUnavailable`] when no random id could be drawn, or state I/O errors
    /// while persisting the initial record.
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
        let id = self.ids.allocate()?;
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
            match owner.get(&task_id) {
                Ok(mut record) => {
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
                }
                Err(error) => {
                    warn_missing_record(&task_id, &error);
                    drop(owner.events.send(JobEvent {
                        id: task_id.clone(),
                        progress: completed_progress(status, &terminal_progress),
                        status,
                        detail: None,
                    }));
                }
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

    /// Marks running records without a live owner as interrupted and reports each one.
    ///
    /// Only local state errors fail startup; the router probe and the audit entry are
    /// best effort.
    async fn recover(&self, audit: &AuditLog) -> Result<(), JobError> {
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
            let probe = match &record.router {
                Some(router) => self.probe_recovery(router).await,
                None => None,
            };
            let fail_safe_active = probe.map(|(armed, _reboot)| armed);
            let scheduled_reboot = probe.map(|(_armed, reboot)| reboot);
            tracing::warn!(
                job = %record.id,
                router = ?record.router,
                fail_safe_active,
                scheduled_reboot,
                "job interrupted by a restart"
            );
            self.audit_recovered(audit, &record, probe).await;
        }
        Ok(())
    }

    /// Reads `(fail_safe_active, scheduled_reboot)` from the router within the probe bound.
    ///
    /// Returns `None` when the router is unknown, unreachable, slow, or answers unexpectedly.
    async fn probe_recovery(&self, router: &str) -> Option<(bool, bool)> {
        let path = kcc_rci::RciPath::from_segments(["show", "last-change"]).ok()?;
        let probe = async {
            let client = self.registry.client(router).await.ok()?;
            client.show(&path, &()).await.ok()
        };
        let Ok(Some(kcc_rci::RciBody::Json(response))) =
            tokio::time::timeout(RECOVERY_PROBE_BOUND, probe).await
        else {
            return None;
        };
        let active = response
            .value
            .pointer("/fail-safe/active")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let scheduled_reboot = response
            .value
            .pointer("/reboot/scheduled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Some((active, scheduled_reboot))
    }

    /// Appends one `job.recovered` audit entry; failures are logged, never propagated.
    async fn audit_recovered(
        &self,
        audit: &AuditLog,
        record: &JobRecord,
        probe: Option<(bool, bool)>,
    ) {
        let mut params = serde_json::json!({ "job": record.id });
        if let (Some((armed, reboot)), Some(object)) = (probe, params.as_object_mut()) {
            drop(object.insert("fail_safe_armed".to_owned(), Value::Bool(armed || reboot)));
            drop(object.insert("scheduled_reboot".to_owned(), Value::Bool(reboot)));
        }
        let mut event = AuditEvent::new(
            self.clock.unix_seconds(),
            Actor::new(ActorKind::System, "job-recovery".to_owned()),
            "job.recovered".to_owned(),
        )
        .with_params(params)
        .with_target(record.id.clone())
        .with_result("interrupted".to_owned(), record.id.clone());
        if let Some(router) = &record.router {
            event = event.with_router(router.clone());
        }
        if let Err(error) = audit.append(event).await {
            tracing::warn!(%error, job = %record.id, "job recovery audit entry not written");
        }
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

/// Stable kind of a job error for structured logging without leaking values.
const fn job_error_kind(error: &JobError) -> &'static str {
    match error {
        JobError::NotFound { id: _ } => "not_found",
        JobError::State(_) => "state",
        JobError::Registry(_) => "registry",
        JobError::RouterBusy { router: _ } => "router_busy",
        JobError::IdCollision => "id_collision",
        JobError::IdUnavailable => "id_unavailable",
        JobError::Malformed { path: _ } => "malformed",
    }
}

/// Returns 100 for completion, otherwise the worker's last reported progress.
fn completed_progress(status: JobStatus, progress: &AtomicU8) -> u8 {
    if status == JobStatus::Completed {
        100
    } else {
        progress.load(Ordering::Relaxed)
    }
}

/// Logs a missing completion record with correlation and non-sensitive error kind.
fn warn_missing_record(job: &str, error: &JobError) {
    tracing::warn!(
        job,
        error_kind = job_error_kind(error),
        "job record unavailable at completion"
    );
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

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::{
        future::pending,
        task::{Context, Poll, Waker},
        time::Duration,
    };
    use std::{fs, sync::atomic::Ordering};

    use tokio::{sync::oneshot, time::timeout};

    use super::{JobError, JobRunner, JobStatus, job_id::JobIdAllocator};
    use crate::{
        accounts::Clock, audit::AuditLog, persist::StateStore, registry::RouterRegistry,
        settings::OutboundConfig,
    };

    /// A test clock with a fixed unix timestamp.
    #[derive(Debug)]
    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn unix_seconds(&self) -> u64 {
            self.0
        }
    }

    #[tokio::test]
    #[expect(
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "the assertions define the collision refusal contract"
    )]
    async fn forced_identifier_collision_is_retryable_before_work_starts() -> Result<(), JobError> {
        let temp = tempfile::TempDir::new()
            .map_err(|error| crate::persist::io_error(std::path::Path::new("."), error))?;
        let state = StateStore::open(&temp.path().join("state"))?;
        let registry = Arc::new(RouterRegistry::new(
            state.clone(),
            &[],
            &OutboundConfig::default(),
        )?);
        let audit = AuditLog::spawn(&state).map_err(|_error| JobError::IdUnavailable)?;
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(1_700_000_000));
        let first = JobRunner::open_with_ids(
            state.clone(),
            Arc::clone(&registry),
            audit.clone(),
            Duration::from_secs(100),
            Arc::clone(&clock),
            JobIdAllocator::fixed(),
        )
        .await?;
        let second = JobRunner::open_with_ids(
            state.clone(),
            registry,
            audit,
            Duration::from_secs(100),
            clock,
            JobIdAllocator::fixed(),
        )
        .await?;
        let (release, released) = oneshot::channel();
        drop(
            first
                .start("held".to_owned(), None, false, async move |_context| {
                    drop(released.await);
                    Ok(())
                })
                .await?,
        );
        let work_started = Arc::new(core::sync::atomic::AtomicBool::new(false));
        let observed = Arc::clone(&work_started);

        let collision = second
            .start("refused".to_owned(), None, false, async move |_context| {
                observed.store(true, Ordering::Relaxed);
                Ok(())
            })
            .await;

        assert!(matches!(collision, Err(JobError::IdCollision)));
        assert!(!work_started.load(Ordering::Relaxed));
        release.send(()).map_err(|()| JobError::IdUnavailable)?;
        Ok(())
    }

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
        let runner = JobRunner::open(state.clone(), registry, AuditLog::spawn(&state)?).await?;
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
        let runner = JobRunner::open(state.clone(), registry, AuditLog::spawn(&state)?).await?;
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
        let runner = JobRunner::open(state.clone(), registry, AuditLog::spawn(&state)?).await?;
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
        assert_eq!(terminal.progress, 100);
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
