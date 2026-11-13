//! Cross-process job-owner recovery regression tests.

#![expect(
    clippy::print_stdout,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive a child process and assert persisted lifecycle state"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, fmt, future::pending, time::Duration};
use std::{
    env, fs,
    io::{BufRead as _, BufReader, Read as _, Write as _, stdin, stdout},
    process::{Command as CliCommand, Stdio},
};

use kcc_app::{
    accounts::Clock,
    audit::AuditLog,
    jobs::{JobError, JobRunner, JobStatus},
    persist::StateStore,
    registry::RouterRegistry,
    settings::OutboundConfig,
};
use tempfile::TempDir;
use tokio::{
    sync::{broadcast::error::RecvError, oneshot},
    time::timeout,
};

const CHILD_ENV: &str = "KCC_JOBS_RECOVERY_CHILD";
const STATE_ENV: &str = "KCC_JOBS_RECOVERY_STATE";

type TestResult = Result<(), Box<dyn Error>>;

#[path = "jobs_recovery/interrupted.rs"]
mod interrupted;

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

fn registry(state: &StateStore) -> Result<Arc<RouterRegistry>, Box<dyn Error>> {
    Ok(Arc::new(RouterRegistry::new(
        state.clone(),
        &[],
        &OutboundConfig::default(),
    )?))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_job_stays_running_and_dead_job_becomes_interrupted() -> TestResult {
    if env::var_os(CHILD_ENV).is_some() {
        let state_dir = env::var_os(STATE_ENV).ok_or("child state directory missing")?;
        let state = StateStore::open(state_dir.as_ref())?;
        let runner =
            JobRunner::open(state.clone(), registry(&state)?, AuditLog::spawn(&state)?).await?;
        let id = runner
            .start("held".to_owned(), None, false, async |_context| {
                pending::<Result<(), String>>().await
            })
            .await?;
        println!("{id}");
        stdout().flush()?;
        let mut stop = [0_u8; 1];
        stdin().read_exact(&mut stop)?;
        return Ok(());
    }

    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let executable = env::current_exe()?;
    let mut command = CliCommand::new(executable);
    let mut child = command
        .args([
            "--exact",
            "live_job_stays_running_and_dead_job_becomes_interrupted",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env(STATE_ENV, state.dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("child stdout unavailable")?;
    let mut lines = BufReader::new(stdout).lines();
    let id = loop {
        let line = lines
            .next()
            .ok_or("child exited before publishing job id")??;
        if line.starts_with("job-") {
            break line;
        }
    };

    let observer =
        JobRunner::open(state.clone(), registry(&state)?, AuditLog::spawn(&state)?).await?;
    assert_eq!(observer.get(&id)?.status, JobStatus::Running);

    child.kill()?;
    let output = child.wait_with_output()?;
    assert!(!output.status.success(), "holder must terminate abruptly");
    let recovery =
        JobRunner::open(state.clone(), registry(&state)?, AuditLog::spawn(&state)?).await?;
    assert_eq!(recovery.get(&id)?.status, JobStatus::Interrupted);
    Ok(())
}

#[tokio::test]
async fn open_prunes_only_expired_finished_jobs() -> TestResult {
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let jobs = state.dir().join("jobs");
    fs::create_dir_all(&jobs)?;
    let now = 1_800_000_000;
    for (id, status, updated_at) in [
        ("job-old", JobStatus::Completed, now - 101),
        ("job-new", JobStatus::Failed, now - 99),
        ("job-running", JobStatus::Running, now - 1_000),
    ] {
        let encoded_status = serde_json::to_value(status)?;
        fs::write(
            jobs.join(format!("{id}.json")),
            serde_json::to_vec(&serde_json::json!({
                "id": id,
                "kind": "test",
                "router": null,
                "write": false,
                "status": encoded_status,
                "progress": 0_u8,
                "created_at": updated_at,
                "updated_at": updated_at,
                "message": null
            }))?,
        )?;
    }
    let clock: Arc<dyn Clock> = Arc::new(MockClock(now));

    let runner = JobRunner::open_with_retention(
        state.clone(),
        registry(&StateStore::open(&temp.path().join("state"))?)?,
        AuditLog::spawn(&state)?,
        Duration::from_secs(100),
        clock,
    )
    .await?;

    assert!(matches!(runner.get("job-old"), Err(JobError::NotFound { id }) if id == "job-old"));
    assert_eq!(runner.get("job-new")?.status, JobStatus::Failed);
    assert_eq!(runner.get("job-running")?.status, JobStatus::Interrupted);
    Ok(())
}

#[tokio::test]
async fn failed_ownership_claim_releases_router_write_slot() -> TestResult {
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let runner =
        JobRunner::open(state.clone(), registry(&state)?, AuditLog::spawn(&state)?).await?;
    fs::remove_dir_all(state.dir())?;

    let failed = runner
        .start(
            "blocked".to_owned(),
            Some("router".to_owned()),
            true,
            async |_context| Ok(()),
        )
        .await;
    assert!(matches!(failed, Err(JobError::State(_))));
    fs::create_dir_all(state.dir())?;

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

#[tokio::test]
async fn runners_sharing_state_start_same_second_jobs() -> TestResult {
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let clock: Arc<dyn Clock> = Arc::new(MockClock(1_800_000_000));
    let first = JobRunner::open_with_retention(
        state.clone(),
        registry(&state)?,
        AuditLog::spawn(&state)?,
        Duration::from_secs(100),
        Arc::clone(&clock),
    )
    .await?;
    let second_state = StateStore::open(&temp.path().join("state"))?;
    let second = JobRunner::open_with_retention(
        second_state.clone(),
        registry(&second_state)?,
        AuditLog::spawn(&second_state)?,
        Duration::from_secs(100),
        clock,
    )
    .await?;
    let mut first_events = first.subscribe();
    let mut second_events = second.subscribe();
    let (release_first, first_released) = oneshot::channel();
    let (release_second, second_released) = oneshot::channel();

    let first_id = first
        .start("first".to_owned(), None, false, async move |_context| {
            drop(first_released.await);
            Ok(())
        })
        .await?;
    let second_id = second
        .start("second".to_owned(), None, false, async move |_context| {
            drop(second_released.await);
            Ok(())
        })
        .await?;

    assert_ne!(first_id, second_id);
    release_first.send(()).map_err(|()| "first job stopped")?;
    release_second.send(()).map_err(|()| "second job stopped")?;
    timeout(Duration::from_secs(2), async {
        loop {
            if first_events.recv().await?.id == first_id {
                break Ok::<(), RecvError>(());
            }
        }
    })
    .await??;
    timeout(Duration::from_secs(2), async {
        loop {
            if second_events.recv().await?.id == second_id {
                break Ok::<(), RecvError>(());
            }
        }
    })
    .await??;
    Ok(())
}
