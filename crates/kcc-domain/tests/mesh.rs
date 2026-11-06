//! Mesh-domain integration coverage.

#![expect(
    clippy::absolute_paths,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::std_instead_of_alloc,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

use core::{error::Error, str::FromStr as _};
use std::sync::Arc;

use kcc_app::{
    audit::{Actor, ActorKind, AuditLog},
    backups::BackupStore,
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    secrets::MasterKey,
    settings::OutboundConfig,
    workflow::ChangeWorkflow,
};
use kcc_catalog::Catalog;
use kcc_domain::{RouterCtx, mesh, mesh::RebootError};
use kcc_rci::{
    OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials,
    capabilities::RouterInfo,
};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile};
use secrecy::SecretString;
use tempfile::TempDir;
use url::Url;

#[tokio::test]
async fn member_fixture_is_read_into_tolerant_model() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn().await?;

    let members = mesh::read_members(&fixture.context).await?;

    assert_eq!(members.len(), 1);
    assert_eq!(
        members.first().and_then(|member| member.id.as_deref()),
        Some("Extender0")
    );
    assert_eq!(members.first().and_then(|member| member.online), Some(true));
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn unconfirmed_member_reboot_sends_no_request() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn().await?;
    let mut changes = fixture.changes().await?;
    let requests_before = fixture.handle.request_count();

    let result = mesh::reboot_member(&mut changes, &fixture.context, "Extender0", "wrong").await;

    assert!(matches!(result, Err(RebootError::ConfirmationMismatch)));
    assert_eq!(fixture.handle.request_count(), requests_before);
    drop(changes);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn ordinary_actions_are_catalog_validated() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn().await?;

    let acquire = mesh::plan_acquire(&fixture.context, "candidate-1")?;
    let check = mesh::plan_update_check(&fixture.context, "Extender0")?;
    let start = mesh::plan_update_start(&fixture.context, "Extender0")?;

    assert_eq!(
        acquire
            .requests
            .first()
            .map(|request| request.path.as_str()),
        Some("mws acquire")
    );
    assert_eq!(
        check.requests.first().map(|request| request.path.as_str()),
        Some("mws member update check")
    );
    assert_eq!(
        start.requests.first().map(|request| request.path.as_str()),
        Some("mws member update start")
    );
    fixture.shutdown().await?;
    Ok(())
}

struct Fixture {
    directory: TempDir,
    handle: kcc_testkit::Handle,
    context: RouterCtx,
    workflow: Arc<ChangeWorkflow>,
}

impl Fixture {
    async fn spawn() -> Result<Self, Box<dyn Error>> {
        let router = FakeRouter::builder(Profile::default())
            .faults(FaultInjection::default())
            .build()?;
        let (address, handle) = router.serve(([127, 0, 0, 1], 0).into()).await?;
        let directory = TempDir::new()?;
        let password = directory.path().join("password");
        std::fs::write(&password, DEFAULT_PASSWORD)?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
        registry
            .create(
                &admin_role(),
                ManagedRouterProfile::new(
                    "router".to_owned(),
                    Url::parse(&format!("http://{address}"))?,
                    DEFAULT_LOGIN.to_owned(),
                    password,
                ),
            )
            .await?;
        let origin = RouterUrl::from_str(&format!("http://{address}"))?;
        let credentials = Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
        );
        let options = RciClientOptions::default()
            .with_outbound(OutboundPolicy::default().with_loopback(true));
        let client = Arc::new(RciClient::connect_with(origin.clone(), credentials, options).await?);
        let manager = kcc_rci::session::SessionManager::with_defaults(
            origin.clone(),
            Credentials::new(
                DEFAULT_LOGIN.to_owned(),
                SecretString::from(DEFAULT_PASSWORD.to_owned()),
            ),
        )?;
        let info = RouterInfo::detect(&manager, &origin).await?;
        let catalog = Catalog::for_router(&info)?;
        let backups = Arc::new(BackupStore::new(
            state.clone(),
            MasterKey::from_bytes([7_u8; 32]),
        ));
        let audit = AuditLog::spawn(&state)?;
        let workflow = ChangeWorkflow::new(state, registry, backups, audit);
        Ok(Self {
            directory,
            handle,
            context: RouterCtx::new(client, catalog),
            workflow,
        })
    }

    async fn changes(&self) -> Result<kcc_app::workflow::ChangeSet, Box<dyn Error>> {
        Ok(self
            .workflow
            .begin(
                "router",
                Actor::new(ActorKind::Cli, "test".to_owned()),
                &admin_role(),
                None,
                false,
            )
            .await?)
    }

    async fn shutdown(self) -> Result<(), Box<dyn Error>> {
        let Self {
            directory,
            handle,
            context: _,
            workflow: _,
        } = self;
        handle.shutdown().await?;
        drop(directory);
        Ok(())
    }
}

fn admin_role() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}
