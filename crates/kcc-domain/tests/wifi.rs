//! Wi-Fi domain integration coverage.

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
use kcc_domain::{RouterCtx, wifi};
use kcc_rci::{
    ObjectName, OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials,
    capabilities::RouterInfo,
};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile};
use secrecy::SecretString;
use tempfile::TempDir;
use url::Url;

#[tokio::test]
async fn ssid_change_is_verified_and_slash_read_uses_post() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn().await?;
    let name = ObjectName::try_from("WifiMaster1/AccessPoint0".to_owned())?;
    let operation = wifi::plan_ssid(&fixture.context, &name, "changed-ssid")?;
    let mut changes = fixture.changes().await?;

    let result = changes
        .apply_cli(wifi::change_request(&name, &operation)?)
        .await?;
    let access_point = wifi::read_access_point(&fixture.context, &name).await?;

    assert!(result.unsaved);
    assert_eq!(access_point.ssid.as_deref(), Some("changed-ssid"));
    let records = fixture.handle.request_log();
    assert!(
        records
            .iter()
            .any(|record| record.method().as_str() == "POST" && record.path() == "/rci/")
    );
    assert!(
        !records
            .iter()
            .any(|record| record.path().contains("/AccessPoint0"))
    );
    drop(changes);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn radios_and_stations_are_typed_from_show_data() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn().await?;

    let radios = wifi::read_radios(&fixture.context).await?;
    let stations = wifi::read_stations(&fixture.context).await?;

    assert_eq!(
        radios
            .get("WifiMaster0")
            .and_then(|radio| radio.band.as_deref()),
        Some("2.4")
    );
    assert_eq!(
        radios
            .get("WifiMaster1")
            .and_then(|radio| radio.band.as_deref()),
        Some("5")
    );
    assert_eq!(stations.len(), 4);
    assert!(stations.iter().all(|station| station.interface.is_some()));
    fixture.shutdown().await?;
    Ok(())
}

#[test]
fn ns3_verification_checks_presence_and_length_without_decoding() {
    let plausible = "A".repeat(24);

    let present = wifi::ns3_presence(Some(&plausible));
    let malformed = wifi::ns3_presence(Some("short"));
    let absent = wifi::ns3_presence(None);

    assert!(present.present);
    assert_eq!(present.encoded_length, Some(24));
    assert!(present.plausible_length);
    assert!(malformed.present);
    assert!(!malformed.plausible_length);
    assert!(!absent.present);
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
