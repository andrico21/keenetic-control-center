//! Interface-domain integration coverage.

#![expect(
    clippy::absolute_paths,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::std_instead_of_alloc,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

use core::{error::Error, net::IpAddr, str::FromStr as _};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

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
use kcc_catalog::{Catalog, Risk};
use kcc_domain::{RouterCtx, configuration, interfaces, interfaces::ManagementVerdict};
use kcc_rci::{
    ObjectName, OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials,
    capabilities::RouterInfo,
};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile};
use secrecy::SecretString;
use tempfile::TempDir;
use url::Url;

#[test]
fn direct_origin_address_classifies_isp_and_excludes_other_interfaces() -> Result<(), Box<dyn Error>>
{
    let interfaces =
        serde_json::from_value::<BTreeMap<String, interfaces::Interface>>(serde_json::json!({
            "ISP":{"id":"ISP","type":"GigabitEthernet","address":"203.0.113.11"},
            "WifiMaster1/AccessPoint0":{"id":"WifiMaster1/AccessPoint0","type":"AccessPoint"}
        }))?;
    let hosts = BTreeSet::from(["203.0.113.11".parse::<IpAddr>()?]);
    let isp = ObjectName::try_from("ISP".to_owned())?;
    let access_point = ObjectName::try_from("WifiMaster1/AccessPoint0".to_owned())?;

    let isp_verdict = interfaces::management::classify_direct(&isp, &hosts, &interfaces);
    let access_point_verdict =
        interfaces::management::classify_direct(&access_point, &hosts, &interfaces);

    assert_eq!(isp_verdict, ManagementVerdict::Management);
    assert_eq!(access_point_verdict, ManagementVerdict::NotManagement);
    Ok(())
}

#[test]
fn unknown_falls_back_to_bridge0_only() -> Result<(), Box<dyn Error>> {
    let bridge = ObjectName::try_from("Bridge0".to_owned())?;
    let isp = ObjectName::try_from("ISP".to_owned())?;

    assert_eq!(ManagementVerdict::Unknown.risk(&bridge), Risk::Management);
    assert_eq!(ManagementVerdict::Unknown.risk(&isp), Risk::Write);
    Ok(())
}

#[tokio::test]
async fn slash_name_read_uses_root_post() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let name = ObjectName::try_from("WifiMaster1/AccessPoint0".to_owned())?;

    let interface = interfaces::read_interface(&fixture.context, &name).await?;

    assert_eq!(interface.id.as_deref(), Some(name.as_str()));
    let records = fixture.handle.request_log();
    assert!(
        records
            .iter()
            .any(|record| { record.method().as_str() == "POST" && record.path() == "/rci/" })
    );
    assert!(
        !records
            .iter()
            .any(|record| record.path().contains("/AccessPoint0"))
    );
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn bridge_down_requires_confirmation_before_router_access() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let name = ObjectName::try_from("Bridge0".to_owned())?;
    let operation = interfaces::plan_down(&fixture.context, &name, ManagementVerdict::Unknown)?;
    assert_eq!(operation.risk, Risk::Management);
    let mut changes = fixture.changes().await?;
    let requests_before = fixture.handle.request_count();

    let result = interfaces::apply(&mut changes, &fixture.context, &name, operation, false).await;

    assert!(result.is_err_and(|error| error.is_confirmation_required()));
    assert_eq!(fixture.handle.request_count(), requests_before);
    drop(changes);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn directly_detected_isp_down_requires_confirmation_before_router_access()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let name = ObjectName::try_from("ISP".to_owned())?;
    let operation = interfaces::plan_down(&fixture.context, &name, ManagementVerdict::Management)?;
    assert_eq!(operation.risk, Risk::Management);
    let mut changes = fixture.changes().await?;
    let requests_before = fixture.handle.request_count();

    let result = interfaces::apply(&mut changes, &fixture.context, &name, operation, false).await;

    assert!(result.is_err_and(|error| error.is_confirmation_required()));
    assert_eq!(fixture.handle.request_count(), requests_before);
    drop(changes);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn bridge_topology_detection_finds_management_bridge() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let name = ObjectName::try_from("Bridge0".to_owned())?;

    let verdict = interfaces::detect_management(&fixture.context, &name).await?;

    assert_eq!(verdict, ManagementVerdict::Management);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn confirmed_bridge_down_disarms_without_saving() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default()).await?;
    let startup = fixture.handle.startup_config_text();
    let name = ObjectName::try_from("Bridge0".to_owned())?;
    let operation = interfaces::plan_down(&fixture.context, &name, ManagementVerdict::Unknown)?;
    let mut changes = fixture.changes().await?;

    let result = interfaces::apply(&mut changes, &fixture.context, &name, operation, true).await?;

    assert!(result.unsaved);
    let interface = interfaces::read_interface(&fixture.context, &name).await?;
    assert_eq!(interface.state.as_deref(), Some("down"));
    let last_change = configuration::read_last_change(&fixture.context).await?;
    assert_eq!(last_change.unsaved, Some(true));
    assert_eq!(
        last_change
            .fail_safe
            .as_ref()
            .and_then(|state| state.active),
        Some(false)
    );
    assert_eq!(fixture.handle.startup_config_text(), startup);
    drop(changes);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn unarmed_fail_safe_refuses_the_risky_change_unsent() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(FaultInjection::default().fail_safe_arm_noop(true)).await?;
    let name = ObjectName::try_from("Bridge0".to_owned())?;
    let operation = interfaces::plan_down(&fixture.context, &name, ManagementVerdict::Unknown)?;
    let mut changes = fixture.changes().await?;

    let refused = interfaces::apply(&mut changes, &fixture.context, &name, operation, true).await;

    assert!(
        refused
            .as_ref()
            .is_err_and(interfaces::InterfaceChangeError::is_fail_safe_unarmed),
        "{refused:?}"
    );
    let log = fixture.handle.request_log();
    let arm_attempt = log
        .iter()
        .position(|record| {
            record.command() == Some("system configuration fail-safe timer reboot 300")
        })
        .ok_or("the fail-safe arming command was not sent")?;
    let read_back = log
        .iter()
        .rposition(|record| record.path().contains("last-change"))
        .ok_or("the fail-safe state was not read back")?;
    assert!(arm_attempt < read_back, "arming precedes its read-back");
    assert_eq!(read_back + 1, log.len(), "nothing follows the read-back");
    assert!(
        !log.iter()
            .any(|record| record.command() == Some("interface Bridge0 down")),
        "the risky change was never sent"
    );
    let interface = interfaces::read_interface(&fixture.context, &name).await?;
    assert_ne!(interface.state.as_deref(), Some("down"));
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
