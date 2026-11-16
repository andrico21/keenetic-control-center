//! Job lock-file and final-record bookkeeping regression tests.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests assert persisted bookkeeping"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, fmt, time::Duration};
use std::{
    fs,
    io::{self, Write},
    sync::Mutex,
};

use kcc_app::{
    accounts::Clock,
    audit::AuditLog,
    jobs::{JobRunner, JobStatus, JobTarget},
    persist::StateStore,
    registry::RouterRegistry,
    settings::OutboundConfig,
};
use tempfile::TempDir;
use tokio::sync::oneshot;
use tracing::{Level, subscriber::set_default};

type TestResult = Result<(), Box<dyn Error>>;

struct MockClock(u64);

impl fmt::Debug for MockClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MockClock").field(&self.0).finish()
    }
}

impl Clock for MockClock {
    fn unix_seconds(&self) -> u64 {
        self.0
    }
}

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_error| io::Error::other("capture poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn runner_at(state: &StateStore, now: u64) -> Result<Arc<JobRunner>, Box<dyn Error>> {
    let registry = Arc::new(RouterRegistry::new(
        state.clone(),
        &[],
        &OutboundConfig::default(),
    )?);
    let clock: Arc<dyn Clock> = Arc::new(MockClock(now));
    Ok(JobRunner::open_with_retention(
        state.clone(),
        registry,
        AuditLog::spawn(state)?,
        Duration::from_secs(100),
        clock,
    )
    .await?)
}

/// B-09: finished jobs leave no `job-*.lock` files once their records are pruned.
#[tokio::test]
async fn pruned_jobs_leave_no_lock_files() -> TestResult {
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let runner = runner_at(&state, 1_800_000_000).await?;
    let mut ids = Vec::new();
    for _ in 0_u8..3 {
        ids.push(
            runner
                .start(
                    "quick".to_owned(),
                    JobTarget::Read(None),
                    async |_context| Ok(()),
                )
                .await?,
        );
    }
    let report = runner.drain(Duration::from_secs(10)).await;
    assert_eq!(report.still_running, 0);

    let later = runner_at(&state, 1_800_000_101).await?;

    for id in &ids {
        assert!(later.get(id).is_err(), "finished record {id} is pruned");
    }
    let leftovers = fs::read_dir(state.dir())?
        .map(|entry| entry.map(|listed| listed.file_name()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(|name| name.to_str().map(str::to_owned))
        .filter(|name| {
            name.starts_with("job-") && name.rsplit_once('.').is_some_and(|(_, ext)| ext == "lock")
        })
        .collect::<Vec<_>>();
    assert!(leftovers.is_empty(), "leftover lock files: {leftovers:?}");
    Ok(())
}

/// B-10: a lost final record write is logged with its error kind.
#[tokio::test]
async fn lost_final_record_write_is_logged() -> TestResult {
    let capture = Capture(Arc::new(Mutex::new(Vec::new())));
    let sink = capture.clone();
    let _subscriber = set_default(
        tracing_subscriber::fmt()
            .with_max_level(Level::WARN)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish(),
    );
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let runner = runner_at(&state, 1_800_000_000).await?;
    let mut events = runner.subscribe();
    let (release, released) = oneshot::channel::<()>();
    let id = runner
        .start(
            "lost".to_owned(),
            JobTarget::Read(None),
            async move |_context| {
                drop(released.await);
                Ok(())
            },
        )
        .await?;
    fs::create_dir_all(state.dir().join("jobs").join(format!(".{id}.json.tmp")))?;
    release.send(()).map_err(|()| "job task ended early")?;
    loop {
        let event = events.recv().await?;
        if event.id == id && event.status != JobStatus::Running {
            break;
        }
    }

    let output = String::from_utf8(
        capture
            .0
            .lock()
            .map_err(|_error| "capture poisoned")?
            .clone(),
    )?;
    assert!(output.contains(&id), "log names the job: {output}");
    assert!(
        output.contains("error_kind=\"state\"") || output.contains("error_kind=state"),
        "log carries the error kind: {output}"
    );
    Ok(())
}
