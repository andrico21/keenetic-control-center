//! System domain integration coverage.

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
    workflow::{ChangeWorkflow, WorkflowError},
};
use kcc_catalog::Catalog;
use kcc_domain::{DomainError, RouterCtx, system};
use kcc_rci::{
    OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials,
    capabilities::RouterInfo,
};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection,
    model::{Firmware, Model, Profile},
};
use secrecy::SecretString;
use tempfile::TempDir;
use url::Url;

#[tokio::test]
async fn reads_system_models_on_both_profiles() -> Result<(), Box<dyn Error>> {
    for firmware in [Firmware::V4_3, Firmware::V5_1] {
        let fixture = Fixture::spawn(firmware, FaultInjection::default()).await?;
        let version = system::read_version(&fixture.context).await?;
        let state = system::read_system(&fixture.context).await?;
        let clock = system::read_clock_date(&fixture.context).await?;
        assert_eq!(version.hw_id.as_deref(), Some("KN-1811"));
        assert_eq!(state.hostname.as_deref(), Some("host-1"));
        assert_eq!(clock.year, Some(2026));
        fixture.handle.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn hostname_silent_noop_is_detectable_by_verification_spec() -> Result<(), Box<dyn Error>> {
    for firmware in [Firmware::V4_3, Firmware::V5_1] {
        let fixture = Fixture::spawn(
            firmware,
            FaultInjection::default().silent_noop_path("system"),
        )
        .await?;
        let operation = system::plan_hostname(&fixture.context, "changed-host")?;
        let request = system::change_request(&operation)?;
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
        let error = match changes.apply(request).await {
            Err(error) => error,
            Ok(_result) => return Err("silent no-op passed hostname read-back verification".into()),
        };
        assert!(matches!(
            error,
            WorkflowError::VerificationFailed { field } if field == "/name"
        ));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn hostname_and_timezone_writes_verify_and_reach_running_config() -> Result<(), Box<dyn Error>>
{
    for firmware in [Firmware::V4_3, Firmware::V5_1] {
        let fixture = Fixture::spawn(firmware, FaultInjection::default()).await?;
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

        let _hostname = changes
            .apply(system::change_request(&system::plan_hostname(
                &fixture.context,
                "changed-host",
            )?)?)
            .await?;
        let _timezone = changes
            .apply(system::change_request(&system::plan_timezone(
                &fixture.context,
                "Europe/Berlin",
            )?)?)
            .await?;

        let running = fixture.handle.running_config_text();
        assert!(
            running.contains("system hostname changed-host"),
            "{running}"
        );
        assert!(
            running.contains("system clock timezone Europe/Berlin"),
            "{running}"
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn timezone_plans_the_catalog_locality_argument() -> Result<(), Box<dyn Error>> {
    for firmware in [Firmware::V4_3, Firmware::V5_1] {
        let fixture = Fixture::spawn(firmware, FaultInjection::default()).await?;
        let before = fixture.handle.request_count();
        let operation = system::plan_timezone(&fixture.context, "Europe/Berlin")?;
        let request = system::change_request(&operation)?;
        assert_eq!(request.catalog_path, "system clock timezone");
        assert_eq!(request.rci_path, ["system", "clock", "timezone"]);
        assert_eq!(
            request.body.redacted(),
            &serde_json::json!({"locality": "Europe/Berlin"})
        );
        assert_eq!(
            fixture.handle.request_count(),
            before,
            "planning sends nothing"
        );
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn factory_reset_refusal_sends_no_request() -> Result<(), Box<dyn Error>> {
    for firmware in [Firmware::V4_3, Firmware::V5_1] {
        let profile = Profile::new(Model::Kn1811, firmware)?;
        let router = FakeRouter::builder(profile).build()?;
        assert!(matches!(
            system::confirm_factory_reset("router", "wrong"),
            Err(DomainError::ConfirmationMismatch)
        ));
        assert_eq!(router.request_count(), 0);
    }
    Ok(())
}

struct Fixture {
    directory: TempDir,
    handle: kcc_testkit::Handle,
    context: RouterCtx,
    workflow: Arc<ChangeWorkflow>,
}

impl Fixture {
    async fn spawn(firmware: Firmware, faults: FaultInjection) -> Result<Self, Box<dyn Error>> {
        let profile = Profile::new(Model::Kn1811, firmware)?;
        let router = FakeRouter::builder(profile).faults(faults).build()?;
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
