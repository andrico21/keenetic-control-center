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
use core::{error::Error, future::pending};
use std::{
    env,
    io::{BufRead as _, BufReader, Read as _, Write as _, stdin, stdout},
    process::{Command as CliCommand, Stdio},
};

use kcc_app::{
    jobs::{JobRunner, JobStatus},
    persist::StateStore,
    registry::RouterRegistry,
    settings::OutboundConfig,
};
use tempfile::TempDir;

const CHILD_ENV: &str = "KCC_JOBS_RECOVERY_CHILD";
const STATE_ENV: &str = "KCC_JOBS_RECOVERY_STATE";

type TestResult = Result<(), Box<dyn Error>>;

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
        let runner = JobRunner::open(state.clone(), registry(&state)?).await?;
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

    let observer = JobRunner::open(state.clone(), registry(&state)?).await?;
    assert_eq!(observer.get(&id)?.status, JobStatus::Running);

    child.kill()?;
    let output = child.wait_with_output()?;
    assert!(!output.status.success(), "holder must terminate abruptly");
    let recovery = JobRunner::open(state.clone(), registry(&state)?).await?;
    assert_eq!(recovery.get(&id)?.status, JobStatus::Interrupted);
    Ok(())
}
