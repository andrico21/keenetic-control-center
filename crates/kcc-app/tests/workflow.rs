//! Workflow integration tests.
#![expect(
    clippy::absolute_paths,
    clippy::assertions_on_result_states,
    clippy::expect_used,
    clippy::missing_errors_doc,
    clippy::std_instead_of_alloc,
    clippy::tests_outside_test_module,
    reason = "integration-test crate structure and direct fixture filesystem setup"
)]

use core::error::Error;
use std::sync::Arc;

use kcc_app::{
    audit::{Actor, ActorKind, AuditLog},
    backups::BackupStore,
    jobs::{JobError, JobRunner},
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    secrets::MasterKey,
    settings::OutboundConfig,
    workflow::{ChangeRequest, ChangeWorkflow, LastChange, VerificationSpec, WorkflowError},
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::oneshot;
use url::Url;

#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test assertions and fixtures define the contract"
)]
#[tokio::test]
async fn first_write_backs_up_once_and_save_is_explicit() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let mut changes = fixture.begin(None).await?;
    let _first_result = changes.apply(description_request("first")).await?;
    let _second_result = changes.apply(description_request("second")).await?;
    assert_eq!(fixture.backups.list("router")?.len(), 1);
    changes.save().await?;
    let last = changes.current_last_change().await?;
    assert!(!last.unsaved);
    fixture.shutdown().await?;
    Ok(())
}

#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test assertions and fixtures define the contract"
)]
#[tokio::test]
async fn silent_noop_names_the_failed_field() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default().silent_noop_path("system")).await?;
    let mut changes = fixture.begin(None).await?;
    let error = changes
        .apply(description_request("not-applied"))
        .await
        .expect_err("silent no-op must fail read-back verification");
    assert!(matches!(
        error,
        WorkflowError::VerificationFailed { field } if field == "/description"
    ));
    fixture.shutdown().await?;
    Ok(())
}

#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test assertions and fixtures define the contract"
)]
#[tokio::test]
async fn stale_read_from_another_agent_conflicts() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let current = fixture.last_change().await?;
    let stale = LastChange::new(
        "different".to_owned(),
        "another-agent".to_owned(),
        current.user,
        current.unsaved,
        current.fail_safe,
    );
    let error = fixture
        .begin(Some(stale))
        .await
        .expect_err("a different agent's intervening change must conflict");
    assert!(matches!(error, WorkflowError::Conflict { agent } if agent == "http/rci"));
    fixture.shutdown().await?;
    Ok(())
}

#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test assertions and fixtures define the contract"
)]
#[tokio::test]
async fn write_jobs_and_cross_process_lease_are_exclusive() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let runner = JobRunner::open(fixture.state.clone(), Arc::clone(&fixture.registry)).await?;
    let (release, released) = oneshot::channel::<()>();
    let first = runner
        .start(
            "write".to_owned(),
            Some("router".to_owned()),
            true,
            async move |_context| {
                drop(released.await);
                Ok(())
            },
        )
        .await?;
    let second = runner
        .start(
            "write".to_owned(),
            Some("router".to_owned()),
            true,
            async |_context| Ok(()),
        )
        .await;
    assert!(matches!(second, Err(JobError::RouterBusy { router }) if router == "router"));

    let changes = fixture.begin(None).await?;
    let second_state = StateStore::open(fixture.state.dir())?;
    assert!(second_state.try_lease("router").is_err());
    drop(changes);
    release.send(()).map_err(|()| "job receiver dropped")?;
    let mut events = runner.subscribe();
    loop {
        let event = events.recv().await?;
        if event.id == first {
            break;
        }
    }
    fixture.shutdown().await?;
    Ok(())
}

struct Fixture {
    directory: TempDir,
    state: StateStore,
    registry: Arc<RouterRegistry>,
    backups: Arc<BackupStore>,
    workflow: Arc<ChangeWorkflow>,
    handle: kcc_testkit::Handle,
}

impl Fixture {
    async fn spawn(faults: FaultInjection) -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let router = FakeRouter::builder(Profile::default())
            .faults(faults)
            .build()?;
        let (address, handle) = router.serve(([127, 0, 0, 1], 0).into()).await?;
        let password = directory.path().join("password");
        std::fs::write(&password, DEFAULT_PASSWORD)?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
        let role = admin_role();
        registry
            .create(
                &role,
                ManagedRouterProfile::new(
                    "router".to_owned(),
                    Url::parse(&format!("http://{address}"))?,
                    "admin".to_owned(),
                    password,
                ),
            )
            .await?;
        let backups = Arc::new(BackupStore::new(
            state.clone(),
            MasterKey::from_bytes([7_u8; 32]),
        ));
        let audit = AuditLog::spawn(&state)?;
        let workflow = ChangeWorkflow::new(
            state.clone(),
            Arc::clone(&registry),
            Arc::clone(&backups),
            audit,
        );
        Ok(Self {
            directory,
            state,
            registry,
            backups,
            workflow,
            handle,
        })
    }

    async fn begin(
        &self,
        last_read: Option<LastChange>,
    ) -> Result<kcc_app::workflow::ChangeSet, WorkflowError> {
        self.workflow
            .begin(
                "router",
                Actor::new(ActorKind::Cli, "test".to_owned()),
                &admin_role(),
                last_read,
                false,
            )
            .await
    }

    async fn last_change(&self) -> Result<LastChange, Box<dyn Error>> {
        let changes = self.begin(None).await?;
        let value = changes.baseline().clone();
        drop(changes);
        Ok(value)
    }

    async fn shutdown(self) -> Result<(), Box<dyn Error>> {
        let Self {
            directory,
            state: _,
            registry: _,
            backups: _,
            workflow: _,
            handle,
        } = self;
        handle.shutdown().await?;
        drop(directory);
        Ok(())
    }
}

fn admin_role() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

fn description_request(value: &str) -> ChangeRequest {
    ChangeRequest::new(
        "system description".to_owned(),
        vec!["system".to_owned()],
        json!({"description": value}),
        vec![VerificationSpec::new(
            vec!["system".to_owned()],
            "/description".to_owned(),
            Value::String(value.to_owned()),
        )],
        json!({"field":"description"}),
    )
}
