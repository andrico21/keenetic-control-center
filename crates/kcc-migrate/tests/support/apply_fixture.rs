//! Shared workflow and inventory fixture for migration acceptance.

use alloc::{collections::BTreeSet, sync::Arc};
use core::{error::Error, fmt::Write as _, str::FromStr as _};

use kcc_app::{
    audit::{Actor, ActorKind, AuditLog},
    backups::BackupStore,
    jobs::JobRunner,
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    secrets::MasterKey,
    settings::OutboundConfig,
    workflow::ChangeWorkflow,
};
use kcc_config::config_text::{flatten, parse};
use kcc_migrate::{
    apply::{ApplyRequest, ApplySource},
    inventory::{InventoryClient, TargetInventory, source_version},
    planner::{Choices, MigrationMaps, Planner},
    source::SourceConfig,
};
use kcc_rci::{RouterUrl, SecretBytes};
use kcc_testkit::{FakeRouter, FaultInjection, Handle, migration, model::Profile};
use tempfile::TempDir;
use tokio::fs;
use url::Url;

/// Real registry, workflow and router with isolated state.
pub(super) struct Fixture {
    /// Temporary state owner.
    pub _directory: TempDir,
    /// Target router handle.
    pub handle: Handle,
    /// Target origin.
    pub url: RouterUrl,
    /// Workflow service.
    pub workflow: Arc<ChangeWorkflow>,
    /// Audit writer.
    pub audit: AuditLog,
    /// Operator role.
    pub role: Role,
    /// Persisted job runner.
    pub runner: Arc<JobRunner>,
    /// Registered target clients.
    pub registry: Arc<RouterRegistry>,
    /// Encrypted source backups.
    pub backups: Arc<BackupStore>,
    /// Audit state directory.
    pub state: StateStore,
}

impl Fixture {
    /// Spawns an isolated router and its application services.
    ///
    /// # Errors
    /// Returns fixture setup errors.
    // NOT cancel-safe: creates isolated files and a background router.
    pub(super) async fn spawn(
        profile: Profile,
        faults: FaultInjection,
    ) -> Result<Self, Box<dyn Error>> {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        Self::from_router(
            FakeRouter::builder(profile)
                .faults(faults)
                .build()?
                .with_migration(scenario),
            "admin",
        )
        .await
    }

    /// Opens application services around a customized router.
    ///
    /// # Errors
    /// Returns fixture setup failures.
    // NOT cancel-safe: starts a server and writes temporary state.
    pub(super) async fn from_router(
        router: FakeRouter,
        password: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let (address, handle) = router.serve(([127, 0, 0, 1], 0).into()).await?;
        let password_file = directory.path().join("password");
        fs::write(&password_file, password).await?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
        let role = Role::new("admin".to_owned(), Permission::ALL, Vec::new());
        let url = RouterUrl::from_str(&format!("http://{address}"))?;
        registry
            .create(
                &role,
                ManagedRouterProfile::new(
                    "target".to_owned(),
                    Url::parse(url.as_str())?,
                    "admin".to_owned(),
                    password_file,
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
            audit.clone(),
        );
        let runner = JobRunner::open(state.clone(), Arc::clone(&registry)).await?;
        Ok(Self {
            _directory: directory,
            handle,
            url,
            workflow,
            audit,
            role,
            runner,
            registry,
            backups,
            state,
        })
    }

    /// Plans distinct Giga interface descriptions against the live target inventory.
    ///
    /// # Errors
    /// Returns inventory or planning failures.
    // cancel-safe: planning reads only.
    pub(super) async fn request(&self, count: usize) -> Result<ApplyRequest, Box<dyn Error>> {
        let mut text = "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\n".to_owned();
        for index in 1..=count {
            writeln!(
                text,
                "interface Bridge{}\n description migrated-{index}\n!",
                index.saturating_add(10)
            )?;
        }
        self.plan_text(text, &Choices::default()).await
    }

    /// Builds a reviewed request for custom source configuration.
    ///
    /// # Errors
    /// Returns inventory and planning failures.
    // cancel-safe: planning only reads.
    pub(super) async fn plan_text(
        &self,
        text: String,
        choices: &Choices,
    ) -> Result<ApplyRequest, Box<dyn Error>> {
        let source = SourceConfig::from_bytes(text.as_bytes())?;
        let client = self.registry.bootstrap_client(&self.role, "target").await?;
        let inventory_client = InventoryClient::from_client(&client);
        let inventory =
            TargetInventory::collect(&inventory_client, Some(source_version("4.3.0")?)).await?;
        let plan = Planner::plan(&source, &inventory, &MigrationMaps::default(), choices)?;
        Ok(ApplyRequest::new(
            Arc::clone(&self.workflow),
            self.audit.clone(),
            Actor::new(ActorKind::Cli, "operator".to_owned()),
            self.role.clone(),
            "target".to_owned(),
            plan,
            ApplySource::File(SecretBytes::from(text.into_bytes())),
        ))
    }

    /// Reads normalized saved lines for exact executable-plan comparison.
    ///
    /// # Errors
    /// Returns malformed fixture configuration.
    pub(super) fn flattened_startup(&self) -> Result<BTreeSet<String>, Box<dyn Error>> {
        Ok(flatten(&parse(&self.handle.startup_config_text())?)
            .iter()
            .map(ToString::to_string)
            .collect())
    }
}
