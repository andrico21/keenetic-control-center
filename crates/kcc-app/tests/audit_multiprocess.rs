//! Cross-process audit append serialization regression test.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive child processes and assert their outcomes"
)]

use core::error::Error;
use std::{
    env,
    io::{Read as _, Write as _, stdin},
    process::{Command, Stdio},
};

use kcc_app::{
    audit::{Actor, ActorKind, AuditEvent, AuditLog, verify_chain},
    persist::StateStore,
};
use tempfile::TempDir;

const CHILD_ENV: &str = "KCC_AUDIT_MULTIPROCESS_CHILD";
const STATE_ENV: &str = "KCC_AUDIT_MULTIPROCESS_STATE";
const CHILDREN: u64 = 4;
const ENTRIES_PER_CHILD: u64 = 25;

type TestResult = Result<(), Box<dyn Error>>;

fn event(child: u64, index: u64) -> AuditEvent {
    AuditEvent::new(
        1_700_000_000_u64.saturating_add(index),
        Actor::new(ActorKind::Cli, format!("child-{child}")),
        "test.concurrent_append".to_owned(),
    )
    .with_result("success".to_owned(), format!("child-{child}-{index}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_processes_append_one_contiguous_chain() -> TestResult {
    if let Ok(child) = env::var(CHILD_ENV) {
        let state_dir = env::var_os(STATE_ENV).ok_or("child state directory missing")?;
        let state = StateStore::open(state_dir.as_ref())?;
        let audit = AuditLog::spawn(&state)?;
        let child_index = child.parse::<u64>()?;
        let mut start = [0_u8; 1];
        stdin().read_exact(&mut start)?;
        for index in 0..ENTRIES_PER_CHILD {
            drop(audit.append(event(child_index, index)).await?);
        }
        return Ok(());
    }

    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let audit = AuditLog::spawn(&state)?;
    drop(audit.append(event(CHILDREN, 0)).await?);
    drop(audit);

    let executable = env::current_exe()?;
    let mut children = Vec::new();
    for child in 0..CHILDREN {
        let mut command = Command::new(&executable);
        let process = command
            .args([
                "--exact",
                "concurrent_processes_append_one_contiguous_chain",
            ])
            .env(CHILD_ENV, child.to_string())
            .env(STATE_ENV, state.dir())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        children.push(process);
    }
    for process in &mut children {
        process
            .stdin
            .as_mut()
            .ok_or("child stdin unavailable")?
            .write_all(&[1])?;
    }
    for process in children {
        let output = process.wait_with_output()?;
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let verified = verify_chain(state.dir())?;
    let expected = 1_u64.saturating_add(CHILDREN.saturating_mul(ENTRIES_PER_CHILD));
    assert_eq!(
        u64::try_from(verified.len())?,
        expected,
        "every append is retained"
    );
    for pair in verified.windows(2) {
        let [before, after] = pair else {
            return Err("audit pair has the wrong width".into());
        };
        assert_eq!(
            after.seq,
            before.seq.saturating_add(1),
            "sequence is contiguous"
        );
    }
    Ok(())
}
