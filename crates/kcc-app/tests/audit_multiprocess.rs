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
    io::{BufRead as _, BufReader, Read as _, Write as _, stdin, stdout},
    path::Path,
    process::{Child, ChildStdout, Command, Stdio},
};

use kcc_app::{
    audit::{AUDIT_FILE_NAME, Actor, ActorKind, AuditEvent, AuditLog, verify_chain},
    persist::StateStore,
};
use tempfile::TempDir;

const CHILD_ENV: &str = "KCC_AUDIT_MULTIPROCESS_CHILD";
const STATE_ENV: &str = "KCC_AUDIT_MULTIPROCESS_STATE";
const HOLD_ENV: &str = "KCC_AUDIT_MULTIPROCESS_HOLD";
const LOCKED: &str = "audit-lock-held";
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
#[expect(
    clippy::disallowed_methods,
    reason = "re-runs this test binary as concurrent child processes that append to one audit chain"
)]
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

/// Another process holding the audit append lock until it is released.
struct LockHolder {
    /// The holding process; it releases the lock when its stdin closes.
    child: Child,
    /// The holder's output, read to its end before it exits.
    output: BufReader<ChildStdout>,
}

impl LockHolder {
    /// Starts `test` again as a process that takes the append lock of `state_dir`, and
    /// returns once it holds the lock.
    #[expect(
        clippy::disallowed_methods,
        reason = "re-runs this test binary as a child that holds the audit append lock"
    )]
    fn spawn(state_dir: &Path, test: &str) -> Result<Self, Box<dyn Error>> {
        let mut child = Command::new(env::current_exe()?)
            .args(["--exact", test, "--nocapture"])
            .env(HOLD_ENV, state_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut output = BufReader::new(child.stdout.take().ok_or("holder stdout unavailable")?);
        let held = output
            .by_ref()
            .lines()
            .map_while(Result::ok)
            .any(|line| line == LOCKED);
        if !held {
            return Err("the holder never took the lock".into());
        }
        Ok(Self { child, output })
    }

    /// Releases the lock and waits for the holder to exit.
    fn release(mut self) -> TestResult {
        drop(self.child.stdin.take());
        let mut rest = String::new();
        let _: usize = self.output.read_to_string(&mut rest)?;
        assert!(self.child.wait()?.success(), "the holder failed: {rest}");
        Ok(())
    }
}

/// In a holder process: takes the append lock, says so, and keeps it until stdin closes.
fn hold_when_holder() -> Option<TestResult> {
    let state_dir = env::var_os(HOLD_ENV)?;
    Some((|| {
        let lock = StateStore::open(state_dir.as_ref())?.try_lock(AUDIT_FILE_NAME)?;
        let mut out = stdout();
        writeln!(out, "{LOCKED}")?;
        out.flush()?;
        let mut rest = Vec::new();
        let _: usize = stdin().read_to_end(&mut rest)?;
        drop(lock);
        Ok(())
    })())
}

/// Entries that wait on another process's append lock past their callers' patience are
/// kept, and written in submission order once the lock is free.
#[tokio::test(start_paused = true)]
async fn entries_waiting_on_another_process_are_kept_in_order() -> TestResult {
    if let Some(held) = hold_when_holder() {
        return held;
    }
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let audit = AuditLog::spawn(&state)?;
    let holder = LockHolder::spawn(
        state.dir(),
        "entries_waiting_on_another_process_are_kept_in_order",
    )?;

    for index in 0..3 {
        let waited = audit.append(event(0, index)).await;
        assert!(waited.is_err(), "the lock is held: {waited:?}");
    }
    holder.release()?;
    drop(audit.append(event(0, 3)).await?);

    let written: Vec<String> = verify_chain(state.dir())?
        .into_iter()
        .map(|entry| entry.request_id)
        .collect();
    assert_eq!(
        written,
        ["child-0-0", "child-0-1", "child-0-2", "child-0-3"],
        "every entry, in submission order"
    );
    Ok(())
}
