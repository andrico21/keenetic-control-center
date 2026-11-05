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
use core::fmt;
use std::{
    fs, io,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{Mutex, broadcast};
use tokio_util::sync::CancellationToken;

use crate::{
    persist::{StateError, StateStore, create_private_dir, io_error, write_atomic},
    registry::{RegistryError, RouterRegistry},
};

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
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct JobEvent {
    /// Job id.
    pub id: String,
    /// Progress percentage.
    pub progress: u8,
    /// Current status.
    pub status: JobStatus,
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
        drop(self.events.send(JobEvent {
            id: self.id.clone(),
            progress: progress.min(100),
            status: JobStatus::Running,
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
        let (events, _receiver) = broadcast::channel(128);
        let runner = Arc::new(Self {
            state,
            registry,
            active: Mutex::new(BTreeMap::new()),
            write_jobs: Mutex::new(BTreeMap::new()),
            events,
            recovery: Mutex::new(Vec::new()),
        });
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

    /// Starts a persisted job and returns its id immediately.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::RouterBusy`] for a second simultaneous write job on one router,
    /// or state I/O errors while persisting the initial record.
    // NOT cancel-safe: once persisted and spawned, the job continues if the caller drops this future.
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
        if write {
            let target = router.as_ref().ok_or_else(|| JobError::RouterBusy {
                router: "missing".to_owned(),
            })?;
            let mut write_jobs = self.write_jobs.lock().await;
            if write_jobs.contains_key(target) {
                return Err(JobError::RouterBusy {
                    router: target.clone(),
                });
            }
            drop(write_jobs.insert(target.clone(), id.clone()));
        }
        let cancellation = CancellationToken::new();
        drop(
            self.active
                .lock()
                .await
                .insert(id.clone(), cancellation.clone()),
        );
        let now = unix_seconds();
        self.persist(&JobRecord {
            id: id.clone(),
            kind,
            router: router.clone(),
            write,
            status: JobStatus::Running,
            progress: 0,
            created_at: now,
            updated_at: now,
            message: None,
        })?;
        let owner = Arc::clone(self);
        let task_id = id.clone();
        drop(tokio::spawn(async move {
            let context = JobContext {
                id: task_id.clone(),
                cancellation: cancellation.clone(),
                events: owner.events.clone(),
            };
            let result = work(context).await;
            let status = if cancellation.is_cancelled() {
                JobStatus::Cancelled
            } else if result.is_ok() {
                JobStatus::Completed
            } else {
                JobStatus::Failed
            };
            if let Ok(mut record) = owner.get(&task_id) {
                record.status = status;
                record.progress = if status == JobStatus::Completed {
                    100
                } else {
                    record.progress
                };
                record.updated_at = unix_seconds();
                record.message = result.err();
                drop(owner.persist(&record));
                drop(owner.events.send(JobEvent {
                    id: task_id.clone(),
                    progress: record.progress,
                    status,
                }));
                if record.write
                    && let Some(target) = record.router
                {
                    drop(owner.write_jobs.lock().await.remove(&target));
                }
            }
            drop(owner.active.lock().await.remove(&task_id));
        }));
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
            record.status = JobStatus::Interrupted;
            record.updated_at = unix_seconds();
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
    let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("job-{}-{sequence}", unix_seconds())
}

/// Returns current Unix seconds.
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
