//! DHCP domain integration coverage.

#![expect(
    clippy::absolute_paths,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::std_instead_of_alloc,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

use core::{error::Error, net::Ipv4Addr, str::FromStr as _};
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
use kcc_domain::{DomainError, RouterCtx, dhcp};
use kcc_rci::{
    OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials,
    capabilities::RouterInfo,
};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, model::Profile};
use secrecy::SecretString;
use tempfile::TempDir;
use url::Url;

#[tokio::test]
async fn static_lease_outside_bound_pool_is_refused_before_write() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn().await?;
    let pool = test_pool();
    let mut changes = fixture.changes().await?;
    let pool_plan = dhcp::plan_pool(&fixture.context, &pool)?;
    drop(dhcp::apply(&mut changes, &fixture.context, &pool_plan).await?);
    let before = fixture.handle.request_log().len();
    let running = fixture.handle.running_config_text();

    let result = dhcp::plan_static_lease(
        &fixture.context,
        "02:00:00:00:10:aa",
        Ipv4Addr::new(198, 51, 100, 25),
    )
    .await;

    assert!(matches!(result, Err(DomainError::StaticLeaseOutsidePool)));
    let requests = fixture.handle.request_log();
    let new_requests = requests.get(before..).ok_or("request log shortened")?;
    assert_ne!(new_requests, []);
    assert!(new_requests.iter().all(|record| matches!(
        record.path(),
        "/auth"
            | "/ci/running-config.txt"
            | "/rci/"
            | "/rci/show/ip/dhcp/bindings"
            | "/rci/show/interface"
    )));
    assert_eq!(fixture.handle.running_config_text(), running);
    drop(changes);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn valid_static_lease_is_verified_through_running_config() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn().await?;
    let pool = test_pool();
    let mut changes = fixture.changes().await?;
    let pool_plan = dhcp::plan_pool(&fixture.context, &pool)?;
    drop(dhcp::apply(&mut changes, &fixture.context, &pool_plan).await?);
    let mac = "02:00:00:00:10:aa";
    let address = Ipv4Addr::new(192, 0, 2, 99);

    let lease = dhcp::plan_static_lease(&fixture.context, mac, address).await?;
    drop(dhcp::apply(&mut changes, &fixture.context, &lease).await?);

    let leases = dhcp::read_static_leases(&fixture.context).await?;
    assert!(leases.iter().any(|entry| {
        entry.mac.as_deref() == Some(mac) && entry.address.as_deref() == Some("192.0.2.99")
    }));
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
        let router = FakeRouter::builder(Profile::default()).build()?;
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
            MasterKey::from_bytes([24_u8; 32]),
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

fn test_pool() -> dhcp::model::PoolConfig {
    dhcp::model::PoolConfig::new(
        "Pool23".to_owned(),
        Ipv4Addr::new(192, 0, 2, 80),
        Ipv4Addr::new(192, 0, 2, 120),
    )
    .with_default_router(Ipv4Addr::new(192, 0, 2, 1))
    .with_dns_servers(vec![Ipv4Addr::new(192, 0, 2, 1)])
    .with_lease_seconds(3600)
    .with_interface("Bridge0".to_owned())
    .with_enabled(true)
}

fn admin_role() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}
