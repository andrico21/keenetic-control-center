//! Startup recovery of stale `Running` records never fails and is audited.

use alloc::sync::Arc;
use core::{error::Error, time::Duration};
use std::fs;

use kcc_app::{
    audit::{AuditEntry, AuditLog, read_entries},
    jobs::{JobRunner, JobStatus},
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    settings::OutboundConfig,
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::time::Instant;
use url::Url;

use super::TestResult;

const JOB_ID: &str = "stale-job";

struct Fixture {
    _directory: TempDir,
    _handle: kcc_testkit::Handle,
    state: StateStore,
    audit: AuditLog,
    registry: Arc<RouterRegistry>,
}

impl Fixture {
    async fn with_router(faults: FaultInjection) -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let (address, handle) = FakeRouter::builder(Profile::default())
            .faults(faults)
            .build()?
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let password = directory.path().join("password");
        fs::write(&password, DEFAULT_PASSWORD)?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
        registry
            .create(
                &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
                ManagedRouterProfile::new(
                    "router".to_owned(),
                    Url::parse(&format!("http://{address}"))?,
                    "admin".to_owned(),
                    password,
                ),
            )
            .await?;
        Ok(Self {
            _directory: directory,
            _handle: handle,
            audit: AuditLog::spawn(&state)?,
            state,
            registry,
        })
    }

    fn write_running(&self, router: &str) -> TestResult {
        let directory = self.state.dir().join("jobs");
        fs::create_dir_all(&directory)?;
        let record = json!({
            "id": JOB_ID,
            "kind": "apply",
            "router": router,
            "write": true,
            "status": "running",
            "progress": 10_u8,
            "created_at": 1_800_000_000_u64,
            "updated_at": 1_800_000_000_u64,
            "message": null,
        });
        fs::write(
            directory.join(format!("{JOB_ID}.json")),
            serde_json::to_vec(&record)?,
        )?;
        Ok(())
    }

    fn recovered_entries(&self) -> Result<Vec<AuditEntry>, Box<dyn Error>> {
        Ok(read_entries(self.state.dir())?
            .into_iter()
            .filter(|entry| entry.action == "job.recovered")
            .collect())
    }
}

#[tokio::test]
async fn unknown_router_is_interrupted_without_failing_open() -> TestResult {
    let fixture = Fixture::with_router(FaultInjection::default()).await?;
    fixture.write_running("gone")?;

    let runner = JobRunner::open(
        fixture.state.clone(),
        Arc::clone(&fixture.registry),
        fixture.audit.clone(),
    )
    .await?;

    assert_eq!(runner.get(JOB_ID)?.status, JobStatus::Interrupted);
    let entries = fixture.recovered_entries()?;
    assert_eq!(entries.len(), 1);
    let entry = entries.first().ok_or("audit entry missing")?;
    assert_eq!(entry.outcome, "interrupted");
    assert_eq!(entry.router.as_deref(), Some("gone"));
    assert_eq!(entry.params_redacted.get("job"), Some(&json!(JOB_ID)));
    assert!(entry.params_redacted.get("fail_safe_armed").is_none());
    Ok(())
}

#[tokio::test]
async fn armed_fail_safe_is_reported_in_the_audit_entry() -> TestResult {
    let fixture = Fixture::with_router(FaultInjection::default()).await?;
    drop(
        fixture
            .registry
            .client("router")
            .await?
            .parse("system configuration fail-safe timer reboot 60")
            .await?,
    );
    fixture.write_running("router")?;

    let runner = JobRunner::open(
        fixture.state.clone(),
        Arc::clone(&fixture.registry),
        fixture.audit.clone(),
    )
    .await?;

    assert_eq!(runner.get(JOB_ID)?.status, JobStatus::Interrupted);
    let entries = fixture.recovered_entries()?;
    let entry = entries.first().ok_or("audit entry missing")?;
    assert_eq!(
        entry.params_redacted.get("fail_safe_armed"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        entry.params_redacted.get("scheduled_reboot"),
        Some(&Value::Bool(false))
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn unreachable_router_does_not_delay_open_past_the_probe_bound() -> TestResult {
    let hour = Duration::from_secs(3_600);
    let fixture = Fixture::with_router(FaultInjection::default().latency(hour)).await?;
    fixture.write_running("router")?;

    let started = Instant::now();
    let runner = JobRunner::open(
        fixture.state.clone(),
        Arc::clone(&fixture.registry),
        fixture.audit.clone(),
    )
    .await?;

    assert!(started.elapsed() <= Duration::from_secs(6));
    assert_eq!(runner.get(JOB_ID)?.status, JobStatus::Interrupted);
    let entries = fixture.recovered_entries()?;
    let entry = entries.first().ok_or("audit entry missing")?;
    assert!(entry.params_redacted.get("fail_safe_armed").is_none());
    Ok(())
}
