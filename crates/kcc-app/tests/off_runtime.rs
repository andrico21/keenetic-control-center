//! Store work of the async APIs runs off the runtime's worker (unix: FIFO gates).
//!
//! Each test runs on a single-threaded runtime. The call under test reads a file the
//! test replaced by a FIFO; a plain thread holds the FIFO's write end and writes it only
//! after the runtime answered while the read was pending (see
//! `kcc_testkit::blocking_gate`). A call blocking the worker cannot let that answer
//! through, so the gate reports no answer.

#![cfg(unix)]
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests assert through the public API"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, time::Duration};
use std::{fs, io, path::Path, process::Command as ChildCommand};

use kcc_app::{
    audit::{Actor, ActorKind, AuditLog},
    backups::{BackupRetention, BackupStore},
    jobs::{JobRunner, JobStatus},
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    secrets::MasterKey,
    settings::OutboundConfig,
    workflow::{ChangeRequest, ChangeWorkflow, VerificationSpec},
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, blocking_gate::BlockingGate};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::time::timeout;
use url::Url;

type TestResult = Result<(), Box<dyn Error>>;

/// How long a gate waits for the runtime's answer.
const GATE: Duration = Duration::from_secs(5);
/// Bound on a whole call under test.
const CALL: Duration = Duration::from_secs(60);

fn admin() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

/// Replaces `path` by a FIFO and returns a gate that writes `bytes` into it.
fn gate(path: &Path, bytes: Vec<u8>) -> Result<BlockingGate, Box<dyn Error>> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let made = ChildCommand::new("mkfifo")
        .args(["-m", "600"])
        .arg(path)
        .status()?;
    assert!(made.success(), "mkfifo failed");
    Ok(BlockingGate::pipe(path.to_owned(), bytes, GATE))
}

fn profile(
    id: &str,
    address: &str,
    password: &Path,
) -> Result<ManagedRouterProfile, Box<dyn Error>> {
    Ok(ManagedRouterProfile::new(
        id.to_owned(),
        Url::parse(&format!("http://{address}"))?,
        "admin".to_owned(),
        password.to_owned(),
    ))
}

/// B-07: the automatic backup of a change (lock, seal, write, retention scan) runs off the
/// runtime's worker: while its retention scan waits on a record nobody wrote yet, the
/// runtime still answers.
#[tokio::test(flavor = "current_thread")]
async fn the_automatic_backup_does_not_block_the_runtime() -> TestResult {
    let directory = TempDir::new()?;
    let (address, handle) = FakeRouter::spawn().await?;
    let password = kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
    let state = StateStore::open(&directory.path().join("state"))?;
    let mut outbound = OutboundConfig::default();
    outbound.allow_loopback = true;
    let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
    registry
        .create(
            &admin(),
            profile("router", &address.to_string(), &password)?,
        )
        .await?;
    let backups = Arc::new(
        BackupStore::new(state.clone(), MasterKey::from_bytes([7_u8; 32]))
            .with_retention(BackupRetention::new(Duration::ZERO, 50)),
    );
    let workflow = ChangeWorkflow::new(
        state.clone(),
        Arc::clone(&registry),
        Arc::clone(&backups),
        AuditLog::spawn(&state)?,
    );
    let mut changes = workflow
        .begin(
            "router",
            Actor::new(ActorKind::Cli, "test".to_owned()),
            &admin(),
            false,
        )
        .await?;
    let records = state.dir().join("backups").join("router");
    fs::create_dir_all(&records)?;
    let held = gate(&records.join("1-held.txt"), b"{}".to_vec())?;
    let request = ChangeRequest::new(
        "system description".to_owned(),
        vec!["system".to_owned()],
        json!({"description": "gated"}),
        vec![VerificationSpec::new(
            vec!["system".to_owned()],
            "/description".to_owned(),
            Value::String("gated".to_owned()),
        )],
        Permission::Write,
        json!({"field": "description"}),
    );

    let (applied, answered) = timeout(CALL, async {
        tokio::join!(changes.apply(request), held.release())
    })
    .await?;

    drop(applied?);
    assert!(
        answered?,
        "the runtime was blocked while the backup was written"
    );
    assert_eq!(backups.list("router")?.len(), 1);
    drop(changes);
    handle.shutdown().await?;
    Ok(())
}

/// B-07: opening the job runner (pruning and recovering records: directory scans, record
/// reads, the interrupted record's write) runs off the runtime's worker.
#[tokio::test(flavor = "current_thread")]
async fn job_recovery_does_not_block_the_runtime() -> TestResult {
    let directory = TempDir::new()?;
    let state = StateStore::open(&directory.path().join("state"))?;
    let registry = Arc::new(RouterRegistry::new(
        state.clone(),
        &[],
        &OutboundConfig::default(),
    )?);
    let jobs = state.dir().join("jobs");
    fs::create_dir_all(&jobs)?;
    let record = json!({
        "id": "gated-job",
        "kind": "test",
        "router": null,
        "write": false,
        "status": "running",
        "progress": 0_u8,
        "created_at": 1_u64,
        "updated_at": 1_u64,
        "message": null,
    });
    let held = gate(&jobs.join("gated-job.json"), serde_json::to_vec(&record)?)?;
    let audit = AuditLog::spawn(&state)?;

    let (opened, answered) = timeout(CALL, async {
        tokio::join!(
            JobRunner::open(state.clone(), registry, audit),
            held.release()
        )
    })
    .await?;

    let runner = opened?;
    assert!(
        answered?,
        "the runtime was blocked while job records were read"
    );
    assert_eq!(runner.get("gated-job")?.status, JobStatus::Interrupted);
    Ok(())
}

/// B-07: a router profile write (lock, read, write and rename of `routers.json`) runs off
/// the runtime's worker.
#[tokio::test(flavor = "current_thread")]
async fn a_profile_write_does_not_block_the_runtime() -> TestResult {
    let directory = TempDir::new()?;
    let password = kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
    let state = StateStore::open(&directory.path().join("state"))?;
    let registry = RouterRegistry::new(state.clone(), &[], &OutboundConfig::default())?;
    registry
        .create(&admin(), profile("first", "192.0.2.1", &password)?)
        .await?;
    let routers = state.dir().join("routers.json");
    let second = profile("second", "192.0.2.2", &password)?;
    let role = admin();
    let held = gate(&routers, fs::read(&routers)?)?;

    let (created, answered) = timeout(CALL, async {
        tokio::join!(registry.create(&role, second), held.release())
    })
    .await?;

    created?;
    assert!(
        answered?,
        "the runtime was blocked while routers.json was written"
    );
    assert_eq!(registry.list()?.len(), 2);
    Ok(())
}
