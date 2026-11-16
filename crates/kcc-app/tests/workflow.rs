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

use core::{error::Error, time::Duration};
use std::sync::Arc;

use kcc_app::{
    audit::{Actor, ActorKind, AuditLog, verify_chain},
    backups::BackupStore,
    jobs::{JobError, JobProgress, JobRunner},
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    secrets::MasterKey,
    settings::OutboundConfig,
    workflow::{
        BatchChangeRequest, BatchItem, ChangeRequest, ChangeWorkflow, CliChangeRequest, CliCommand,
        LastChange, VerificationSpec, WorkflowError,
    },
};
use kcc_catalog::{Catalog, HttpMethod};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::oneshot;
use url::Url;

#[path = "workflow/batch_outcomes.rs"]
mod batch_outcomes;

#[path = "workflow/namespaces.rs"]
mod namespaces;

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
async fn operation_permission_is_enforced_after_read_lease() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let role = Role::new(
        "reader".to_owned(),
        [Permission::Read, Permission::Write],
        vec!["*".to_owned()],
    );
    let mut changes = fixture.begin_with_role(&role).await?;
    let mut request = description_request("denied");
    request.permission = Permission::Destructive;
    let error = changes
        .apply(request)
        .await
        .expect_err("the operation permission must be checked inside apply");
    assert!(matches!(error, WorkflowError::PermissionDenied { router } if router == "router"));
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
async fn dead_audit_writer_refuses_begin_without_a_router_request() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let audit = AuditLog::spawn_with_limit(&fixture.state, 1)?;
    drop(audit.append(test_audit_event(1)).await?);
    std::fs::create_dir_all(fixture.state.dir().join("audit-00000000000000000001.jsonl"))?;
    let failed = audit.append(test_audit_event(2)).await;
    assert!(failed.is_err(), "fatal fixture must fail: {failed:?}");
    assert!(!audit.is_alive(), "fatal fixture must close its writer");
    let workflow = ChangeWorkflow::new(
        fixture.state.clone(),
        Arc::clone(&fixture.registry),
        Arc::clone(&fixture.backups),
        audit,
    );
    let requests = fixture.handle.request_count();

    let result = workflow
        .begin(
            "router",
            Actor::new(ActorKind::Cli, "test".to_owned()),
            &admin_role(),
            None,
            false,
        )
        .await;

    assert!(
        matches!(result, Err(WorkflowError::Audit(_))),
        "dead writer result: {result:?}"
    );
    assert_eq!(fixture.handle.request_count(), requests);
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
async fn cli_mutation_uses_backup_and_read_back_protection() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let info = fixture.registry.poll_info("router").await?;
    let catalog = Catalog::for_router(&info)?;
    let validated = catalog
        .validate(
            "interface description",
            HttpMethod::Post,
            &json!({"description":"cli-protected"}),
        )
        .map_err(|issues| format!("catalog rejected fixture command: {issues:?}"))?;
    let request = CliChangeRequest::new(
        vec![CliCommand::new(
            "interface Bridge0 description cli-protected".to_owned(),
            validated,
        )?],
        vec![VerificationSpec::new(
            vec!["show".to_owned(), "last-change".to_owned()],
            "/unsaved".to_owned(),
            Value::Bool(true),
        )],
        Permission::Write,
        json!({"interface":"Bridge0"}),
    );
    let mut changes = fixture.begin(None).await?;
    let result = changes.apply_cli(request).await?;
    assert!(result.unsaved);
    assert_eq!(result.responses.len(), 1);
    assert_eq!(fixture.backups.list("router")?.len(), 1);
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
async fn cli_audit_distinguishes_persisted_and_unsaved_changes() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let info = fixture.registry.poll_info("router").await?;
    let catalog = Catalog::for_router(&info)?;
    let cases = [
        vec![(
            "system country DE",
            "system country",
            json!({"country":"DE"}),
        )],
        vec![
            (
                "system country US",
                "system country",
                json!({"country":"US"}),
            ),
            (
                "system description cli-unsaved",
                "system description",
                json!({"description":"cli-unsaved"}),
            ),
        ],
    ];
    for command_specs in cases {
        let commands = command_specs
            .into_iter()
            .map(|(line, path, value)| {
                let validated = catalog
                    .validate(path, HttpMethod::Post, &value)
                    .map_err(|issues| format!("catalog rejected fixture command: {issues:?}"))?;
                CliCommand::new(line.to_owned(), validated)
                    .map_err(|error| format!("{line}: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let request = CliChangeRequest::new(
            commands,
            Vec::new(),
            Permission::Write,
            json!({"validated":true}),
        );
        drop(fixture.begin(None).await?.apply_cli(request).await?);
    }
    let outcomes = verify_chain(fixture.state.dir())?
        .into_iter()
        .filter(|entry| entry.action == "router.change_cli")
        .map(|entry| entry.outcome)
        .collect::<Vec<_>>();
    assert_eq!(outcomes, ["applied_persisted", "applied_unsaved"]);
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
async fn terminal_cli_mutation_survives_session_loss_after_preflight() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let info = fixture.registry.poll_info("router").await?;
    let catalog = Catalog::for_router(&info)?;
    let validated = catalog
        .validate("system reboot", HttpMethod::Post, &json!({}))
        .map_err(|issues| format!("catalog rejected terminal command: {issues:?}"))?;
    let request = CliChangeRequest::terminal(
        vec![CliCommand::new("system reboot".to_owned(), validated)?],
        Permission::Destructive,
        json!({"operation":"reboot"}),
    );
    let mut changes = fixture.begin(None).await?;
    let requests_before = fixture.handle.request_count();
    let result = changes.apply_cli(request).await?;
    let requests_after = fixture.handle.request_count();
    assert_eq!(result.responses.len(), 1);
    assert_eq!(requests_after.saturating_sub(requests_before), 3);
    assert_eq!(fixture.backups.list("router")?.len(), 1);
    let entries = verify_chain(fixture.state.dir())?;
    let event = entries.last().ok_or("terminal audit event missing")?;
    assert_eq!(event.action, "router.change_cli_terminal");
    assert_eq!(event.outcome, "applied_state_unknown");
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
async fn terminal_cli_mutation_enforces_operation_permission() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let role = Role::new(
        "writer".to_owned(),
        [Permission::Read, Permission::Write],
        vec!["*".to_owned()],
    );
    let info = fixture.registry.poll_info("router").await?;
    let catalog = Catalog::for_router(&info)?;
    let validated = catalog
        .validate("system reboot", HttpMethod::Post, &json!({}))
        .map_err(|issues| format!("catalog rejected terminal command: {issues:?}"))?;
    let request = CliChangeRequest::terminal(
        vec![CliCommand::new("system reboot".to_owned(), validated)?],
        Permission::Destructive,
        json!({"operation":"reboot"}),
    );
    let mut changes = fixture.begin_with_role(&role).await?;
    let error = changes
        .apply_cli(request)
        .await
        .expect_err("terminal CLI permission must be checked before dispatch");
    assert!(matches!(error, WorkflowError::PermissionDenied { router } if router == "router"));
    assert_eq!(fixture.backups.list("router")?.len(), 0);
    assert_eq!(verify_chain(fixture.state.dir())?.len(), 0);
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
async fn delete_mutation_uses_backup_and_read_back_protection() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let request = ChangeRequest::delete(
        "system description".to_owned(),
        vec!["system".to_owned(), "description".to_owned()],
        json!({}),
        vec![VerificationSpec::new(
            vec!["system".to_owned()],
            String::new(),
            json!({"name":"host-1"}),
        )],
        Permission::Write,
        json!({"field":"description"}),
    );
    let mut changes = fixture.begin(None).await?;
    let result = changes.apply(request).await?;
    assert!(result.unsaved);
    assert_eq!(fixture.backups.list("router")?.len(), 1);
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
async fn delete_mutation_enforces_operation_permission() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let role = Role::new(
        "reader".to_owned(),
        [Permission::Read, Permission::Write],
        vec!["*".to_owned()],
    );
    let request = ChangeRequest::delete(
        "system description".to_owned(),
        vec!["system".to_owned(), "description".to_owned()],
        json!({}),
        Vec::new(),
        Permission::Destructive,
        json!({"field":"description"}),
    );
    let mut changes = fixture.begin_with_role(&role).await?;
    let error = changes
        .apply(request)
        .await
        .expect_err("the operation permission must be checked inside apply");
    assert!(matches!(error, WorkflowError::PermissionDenied { router } if router == "router"));
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
async fn batch_mutation_preserves_responses_and_read_back_protection() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let request = BatchChangeRequest::new(
        vec![
            BatchItem::new(json!({"interface":{"name":"Batch1"}})),
            BatchItem::new(json!({"interface":{"name":"Batch2"}})),
        ],
        vec![VerificationSpec::new(
            vec!["interface".to_owned()],
            "/Batch2".to_owned(),
            json!({}),
        )],
        Permission::Write,
        json!({"items":2_u8}),
    );
    let mut changes = fixture.begin(None).await?;
    let result = changes.apply_batch(request).await?;
    assert!(result.unsaved);
    assert_eq!(result.responses.len(), 2);
    assert!(result.responses.iter().all(Result::is_ok));
    assert_eq!(fixture.backups.list("router")?.len(), 1);
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
async fn batch_mutation_enforces_operation_permission() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let role = Role::new(
        "reader".to_owned(),
        [Permission::Read, Permission::Write],
        vec!["*".to_owned()],
    );
    let request = BatchChangeRequest::new(
        vec![BatchItem::new(json!({"interface":{"name":"Denied"}}))],
        Vec::new(),
        Permission::Destructive,
        json!({"items":1_u8}),
    );
    let mut changes = fixture.begin_with_role(&role).await?;
    let error = changes
        .apply_batch(request)
        .await
        .expect_err("the operation permission must be checked inside apply_batch");
    assert!(matches!(error, WorkflowError::PermissionDenied { router } if router == "router"));
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
    let runner = JobRunner::open(
        fixture.state.clone(),
        Arc::clone(&fixture.registry),
        AuditLog::spawn(&fixture.state)?,
    )
    .await?;
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

#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test assertions and fixtures define the contract"
)]
#[tokio::test]
async fn job_streams_typed_progress_with_latest_percentage() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let runner = JobRunner::open(
        fixture.state.clone(),
        Arc::clone(&fixture.registry),
        AuditLog::spawn(&fixture.state)?,
    )
    .await?;
    let mut events = runner.subscribe();
    let id = runner
        .start("ping".to_owned(), None, false, async |context| {
            context.progress(25);
            context.structured_progress(JobProgress::OutputLine("reply".to_owned()));
            Ok(())
        })
        .await?;
    loop {
        let event = events.recv().await?;
        if event.id == id && event.detail.is_some() {
            assert_eq!(event.progress, 25);
            assert_eq!(
                event.detail,
                Some(JobProgress::OutputLine("reply".to_owned()))
            );
            break;
        }
    }
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
async fn graceful_drain_cancels_job_without_triggering_rollback() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let runner = JobRunner::open(
        fixture.state.clone(),
        Arc::clone(&fixture.registry),
        AuditLog::spawn(&fixture.state)?,
    )
    .await?;
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (rollback_tx, rollback_rx) = oneshot::channel::<()>();
    drop(
        runner
            .start(
                "migration".to_owned(),
                Some("router".to_owned()),
                true,
                async move |context| {
                    started_tx.send(()).map_err(|()| "start observer dropped")?;
                    context.cancellation().cancelled().await;
                    drop(rollback_tx);
                    Ok(())
                },
            )
            .await?,
    );
    started_rx.await?;

    let report = runner.drain(Duration::from_secs(5)).await;

    assert_eq!(report.cancelled, 1);
    assert_eq!(report.still_running, 0);
    assert!(
        rollback_rx.await.is_err(),
        "drain must not request rollback"
    );
    fixture.shutdown().await?;
    Ok(())
}

#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::panic,
    reason = "integration-test assertions and fixtures define the contract"
)]
#[tokio::test(flavor = "current_thread")]
async fn lease_label_released_synchronously_on_drop() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let changes_a = fixture.begin(None).await?;
    drop(changes_a);
    let changes_b = fixture.begin(None).await?;
    let error_c = fixture
        .begin(None)
        .await
        .expect_err("agent C must get RouterBusy");
    let WorkflowError::RouterBusy { actor } = error_c else {
        panic!("expected RouterBusy, got: {error_c:?}");
    };
    assert_eq!(actor, "test");
    drop(changes_b);
    fixture.shutdown().await?;
    Ok(())
}

#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::panic,
    reason = "integration-test assertions and fixtures define the contract"
)]
#[tokio::test(flavor = "current_thread")]
async fn lease_label_cleanup_after_registry_error() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let admin = admin_role();
    let error = fixture
        .workflow
        .begin(
            "unknown-router",
            Actor::new(ActorKind::Cli, "agent-x".to_owned()),
            &admin,
            None,
            false,
        )
        .await;
    assert!(
        error.is_err(),
        "begin on unknown router must fail after label insert"
    );
    let held = fixture.state.try_lease("unknown-router")?;
    let busy_error = fixture
        .workflow
        .begin(
            "unknown-router",
            Actor::new(ActorKind::Cli, "agent-y".to_owned()),
            &admin,
            None,
            false,
        )
        .await
        .expect_err("should get RouterBusy (held by our lease)");
    let WorkflowError::RouterBusy { actor } = busy_error else {
        panic!("expected RouterBusy, got {busy_error:?}");
    };
    assert_eq!(
        actor, "another process",
        "agent-x's label was cleaned up; no stale actor name remains"
    );
    drop(held);
    fixture.shutdown().await?;
    Ok(())
}

/// B-12: a router whose firmware has no catalog is refused as unsupported firmware.
///
/// Not as an invalid `show last-change` response.
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test assertions and fixtures define the contract"
)]
#[tokio::test]
async fn a_router_without_a_catalog_is_unsupported_firmware() -> Result<(), Box<dyn Error>> {
    let version = json!({"title": "3.9.1", "release": "3.9.1", "hw_id": "KN-1811"});
    let fixture = Fixture::spawn_router(
        FakeRouter::builder(Profile::default()).show_fixture("version", version),
    )
    .await?;
    let error = fixture
        .begin(None)
        .await
        .expect_err("a firmware without a catalog cannot be changed");
    assert!(
        matches!(error, WorkflowError::UnsupportedFirmware),
        "{error:?}"
    );
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
        Self::spawn_router(FakeRouter::builder(Profile::default()).faults(faults)).await
    }

    async fn spawn_router(builder: kcc_testkit::FakeRouterBuilder) -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let router = builder.build()?;
        let (address, handle) = router.serve(([127, 0, 0, 1], 0).into()).await?;
        let password =
            kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
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

    async fn begin_with_role(
        &self,
        role: &Role,
    ) -> Result<kcc_app::workflow::ChangeSet, WorkflowError> {
        self.workflow
            .begin(
                "router",
                Actor::new(ActorKind::Cli, "test".to_owned()),
                role,
                None,
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

fn test_audit_event(sequence: u64) -> kcc_app::audit::AuditEvent {
    kcc_app::audit::AuditEvent::new(
        sequence,
        Actor::new(ActorKind::System, "workflow-test".to_owned()),
        "test.audit".to_owned(),
    )
    .with_result("success".to_owned(), format!("audit-{sequence}"))
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
        Permission::Write,
        json!({"field":"description"}),
    )
}
