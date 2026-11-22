//! Mutations started as write jobs.

use alloc::sync::Arc;

use kcc_app::{
    accounts::SystemClock,
    jobs::{JobProgress, JobStatus},
    secrets::MasterKey,
};
use kcc_domain::entware::ssh::{
    SshServices,
    error::EntwareError,
    ops::job::{self, Mutation, Request},
};
use serde_json::json;
use tokio::time::timeout;

use crate::{
    harness::{LIMIT, ROUTER, operator},
    rig::{Rig, package},
    support::TestResult,
};

/// Services shared with a job, over the rig's fixture and key.
fn shared(rig: &Rig) -> Arc<SshServices> {
    let fixture = rig.harness().fixture();
    Arc::new(SshServices::new(
        Arc::clone(fixture.workflow()),
        fixture.registry(),
        fixture.audit().clone(),
        &MasterKey::from_bytes([9_u8; 32]),
        Arc::new(SystemClock::default()),
    ))
}

/// Todo 11: an install started as a job is a write job of the router that installs the
/// package and reports the read-back as structured progress.
#[tokio::test]
async fn an_install_runs_as_a_write_job() -> TestResult {
    let rig = Rig::start().await?;
    let jobs = rig.harness().fixture().jobs().await?;
    let mut events = jobs.subscribe();
    let request = Request::new(
        rig.harness().context().clone(),
        ROUTER.to_owned(),
        rig.harness().alice().clone(),
        rig.harness().admin().clone(),
    );
    let id = job::start(
        &jobs,
        shared(&rig),
        request,
        Mutation::Install(package("htop")?),
    )
    .await?;
    timeout(LIMIT, jobs.ended(&id)).await?;
    let record = jobs.get(&id)?;
    assert_eq!(
        (
            record.status,
            record.write,
            record.kind.as_str(),
            record.router.as_deref()
        ),
        (
            JobStatus::Completed,
            true,
            "entware.ssh.install",
            Some(ROUTER)
        )
    );
    let mut details = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let Some(JobProgress::Structured(value)) = event.detail {
            details.push(value);
        }
    }
    assert_eq!(
        details,
        vec![json!({"package": "htop", "before": null, "after": "3.3.0-1"})]
    );
    assert!(rig.harness().ssh()?.installed().contains_key("htop"));
    Ok(())
}

/// Todo 11: a caller without `Destructive` is refused before any job starts.
#[tokio::test]
async fn a_job_without_destructive_is_refused_before_it_starts() -> TestResult {
    let rig = Rig::start().await?;
    let jobs = rig.harness().fixture().jobs().await?;
    let mut events = jobs.subscribe();
    let request = Request::new(
        rig.harness().context().clone(),
        ROUTER.to_owned(),
        rig.harness().alice().clone(),
        operator(),
    );
    let outcome = job::start(&jobs, shared(&rig), request, Mutation::Update).await;
    assert!(
        matches!(outcome, Err(EntwareError::PermissionDenied)),
        "{outcome:?}"
    );
    assert!(events.try_recv().is_err(), "no job event");
    Ok(())
}
