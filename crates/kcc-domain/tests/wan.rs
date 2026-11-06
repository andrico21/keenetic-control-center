//! WAN-domain integration coverage.

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
use kcc_domain::{RouterCtx, interfaces::ManagementVerdict, wan, wan::StaticAddress};
use kcc_rci::{
    ObjectName, OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials,
    capabilities::RouterInfo,
};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile};
use secrecy::SecretString;
use serde_json::json;
use tempfile::TempDir;
use url::Url;

#[test]
fn connection_decode_replaces_credentials_with_presence() -> Result<(), Box<dyn Error>> {
    let value = json!({
        "id":"PPPoE0","type":"PPPoE","state":"up",
        "authentication":{"identity":"operator","password":{"ns3":"encoded-value"}}
    });

    let connection: wan::Connection = serde_json::from_value(value)?;
    let serialized = serde_json::to_string(&connection)?;

    assert_eq!(connection.kind, Some(wan::ConnectionKind::Pppoe));
    assert!(connection.identity_present);
    assert!(connection.password_present);
    assert!(!serialized.contains("operator"));
    assert!(!serialized.contains("encoded-value"));
    Ok(())
}

#[tokio::test]
async fn non_secret_plans_execute_through_change_set() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn().await?;
    let name = ObjectName::try_from("Ethernet9".to_owned())?;
    let address = StaticAddress::new(
        Ipv4Addr::new(198, 51, 100, 9),
        Ipv4Addr::new(255, 255, 255, 0),
    );
    let mut changes = fixture.changes().await?;

    let create = wan::plan_create(&fixture.context, &name)?;
    let created = changes
        .apply_cli(wan::change_request(&name, &create)?)
        .await?;
    let static_address = wan::plan_static_address(
        &fixture.context,
        &name,
        address,
        ManagementVerdict::NotManagement,
    )?;
    let configured = changes
        .apply_cli(wan::change_request(&name, &static_address)?)
        .await?;

    assert!(created.unsaved);
    assert!(configured.unsaved);
    assert!(
        fixture
            .handle
            .running_config_text()
            .contains("ip address 198.51.100.9 255.255.255.0")
    );
    let delete = wan::plan_delete(&fixture.context, &name)?;
    drop(
        changes
            .apply_cli(wan::change_request(&name, &delete)?)
            .await?,
    );
    assert!(!fixture.handle.running_config_text().contains("Ethernet9"));
    drop(changes);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn fake_router_reads_ipoe_without_authentication_values() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn().await?;

    let connections = wan::read_connections(&fixture.context).await?;

    let isp = connections.get("ISP").ok_or("missing ISP connection")?;
    assert_eq!(isp.kind, Some(wan::ConnectionKind::Ipoe));
    assert!(!isp.identity_present);
    assert!(!isp.password_present);
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
