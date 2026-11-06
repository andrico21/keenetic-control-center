//! Segments domain integration coverage.

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
use kcc_domain::{RouterCtx, segments};
use kcc_rci::{
    OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials,
    capabilities::RouterInfo,
};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile};
use secrecy::SecretString;
use tempfile::TempDir;
use url::Url;

#[tokio::test]
async fn create_then_delete_restores_both_router_stores() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let settings = fixture.handle.settings_snapshot();
    let running = fixture.handle.running_config_text();
    let mut changes = fixture.changes().await?;

    let created = segments::create(&mut changes, &fixture.context, &segment()).await?;
    segments::delete(&mut changes, &fixture.context, created).await?;

    assert_eq!(fixture.handle.settings_snapshot(), settings);
    assert_eq!(fixture.handle.running_config_text(), running);
    drop(changes);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn bridge_failure_rolls_vlan_and_trunks_back() -> Result<(), Box<dyn Error>> {
    let faults = FaultInjection::default().fail_parse_matching("interface Bridge23", 1);
    let fixture = Fixture::spawn(faults).await?;
    let settings = fixture.handle.settings_snapshot();
    let running = fixture.handle.running_config_text();
    let mut changes = fixture.changes().await?;

    let error = match segments::create(&mut changes, &fixture.context, &segment()).await {
        Err(error) => error,
        Ok(_created) => return Err("bridge fault did not fail segment creation".into()),
    };

    assert!(matches!(
        error,
        segments::SegmentError::StepFailed { step, source: _ } if step == "bridge"
    ));
    assert_eq!(fixture.handle.settings_snapshot(), settings);
    assert_eq!(fixture.handle.running_config_text(), running);
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
    async fn spawn(faults: FaultInjection) -> Result<Self, Box<dyn Error>> {
        let router = FakeRouter::builder(Profile::default())
            .faults(faults)
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
            MasterKey::from_bytes([25_u8; 32]),
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

fn segment() -> segments::SegmentSpec {
    segments::SegmentSpec::new(
        23,
        23,
        Ipv4Addr::new(192, 0, 2, 129),
        Ipv4Addr::new(255, 255, 255, 192),
        Ipv4Addr::new(192, 0, 2, 130),
        Ipv4Addr::new(192, 0, 2, 180),
        vec![
            "GigabitEthernet0/0".to_owned(),
            "GigabitEthernet0/1".to_owned(),
            "GigabitEthernet0/2".to_owned(),
            "GigabitEthernet0/3".to_owned(),
            "GigabitEthernet0/4".to_owned(),
        ],
    )
}

fn admin_role() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}
