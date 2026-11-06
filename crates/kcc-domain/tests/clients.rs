//! Clients domain integration coverage.

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
use kcc_domain::{RouterCtx, clients};
use kcc_rci::{
    OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials,
    capabilities::RouterInfo,
};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter,
    model::{Firmware, Model, Profile},
};
use secrecy::SecretString;
use tempfile::TempDir;
use url::Url;

#[tokio::test]
async fn denying_an_unregistered_client_registers_then_blocks_it() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn().await?;
    let mac = "02:00:00:00:10:02";
    let client = clients::read_client(&fixture.context, mac)
        .await?
        .ok_or("fixture client")?;
    assert_eq!(client.registered, Some(false));

    let operation = clients::plan_access(
        &fixture.context,
        &client,
        "blocked-device",
        clients::Access::Deny,
    )?;
    let mut changes = fixture
        .workflow
        .begin(
            "router",
            Actor::new(ActorKind::Cli, "test".to_owned()),
            &admin_role(),
            None,
            false,
        )
        .await?;
    let result = clients::apply(&mut changes, &fixture.context, &operation).await?;

    assert!(result.unsaved);
    let blocked = clients::read_client(&fixture.context, mac)
        .await?
        .ok_or("registered client")?;
    assert_eq!(blocked.name.as_deref(), Some("blocked-device"));
    assert_eq!(blocked.registered, Some(true));
    assert_eq!(blocked.access.as_deref(), Some("deny"));
    drop(changes);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn removing_a_client_uses_known_host_cascade() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn().await?;
    let mac = "02:00:00:00:10:aa";
    let registration = clients::plan_register(&fixture.context, mac, "temporary")?;
    let mut changes = fixture
        .workflow
        .begin(
            "router",
            Actor::new(ActorKind::Cli, "test".to_owned()),
            &admin_role(),
            None,
            false,
        )
        .await?;
    drop(clients::apply(&mut changes, &fixture.context, &registration).await?);

    let removal = clients::plan_remove(&fixture.context, mac)?;
    drop(clients::apply(&mut changes, &fixture.context, &removal).await?);

    assert!(clients::read_client(&fixture.context, mac).await?.is_none());
    drop(changes);
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
        let profile = Profile::new(Model::Kn1811, Firmware::V5_1)?;
        let router = FakeRouter::builder(profile).build()?;
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
            MasterKey::from_bytes([23_u8; 32]),
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
