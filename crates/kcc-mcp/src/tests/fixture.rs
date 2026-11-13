//! A real registry, workflow, and fake router behind one `KccMcp`.

use core::error::Error;
use std::sync::Arc;

use kcc_app::{
    audit::AuditLog,
    backups::BackupStore,
    jobs::JobRunner,
    permissions::{Permission, Role},
    persist::StateStore,
    poller::Poller,
    registry::{ManagedRouterProfile, RouterRegistry},
    secrets::MasterKey,
    settings::{McpConfig, OutboundConfig, PrivacyConfig},
    workflow::ChangeWorkflow,
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, model::Profile};
use tempfile::TempDir;
use url::Url;

use crate::KccMcp;

pub(crate) struct Fixture {
    directory: TempDir,
    server: KccMcp,
    handle: kcc_testkit::Handle,
}

impl Fixture {
    /// Observes commands sent by the synthetic-operation test.
    pub(crate) fn commands(&self) -> Vec<String> {
        self.handle
            .request_log()
            .iter()
            .filter_map(|record| record.command().map(str::to_owned))
            .collect()
    }
    /// The handler under test.
    pub(crate) const fn server(&self) -> &KccMcp {
        &self.server
    }

    /// Requests the fake router received.
    pub(super) fn requests(&self) -> u64 {
        self.handle.request_count()
    }

    pub(crate) async fn spawn(
        config: McpConfig,
        privacy: PrivacyConfig,
    ) -> Result<Self, Box<dyn Error>> {
        Self::spawn_with_role(config, privacy, admin_role()).await
    }

    pub(super) async fn spawn_with_role(
        config: McpConfig,
        privacy: PrivacyConfig,
        fallback_role: Role,
    ) -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let router = FakeRouter::builder(Profile::default()).build()?;
        let (address, handle) = router.serve(([127, 0, 0, 1], 0).into()).await?;
        let password =
            kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
        let admin = admin_role();
        registry
            .create(
                &admin,
                ManagedRouterProfile::new(
                    "lab-1".to_owned(),
                    Url::parse(&format!("http://{address}"))?,
                    "admin".to_owned(),
                    password,
                ),
            )
            .await?;
        let backups = Arc::new(BackupStore::new(
            state.clone(),
            MasterKey::from_bytes([9_u8; 32]),
        ));
        let audit = AuditLog::spawn(&state)?;
        let workflow =
            ChangeWorkflow::new(state.clone(), Arc::clone(&registry), backups, audit.clone());
        let jobs = JobRunner::open(state, Arc::clone(&registry), audit.clone()).await?;
        let poller = Poller::new(Arc::clone(&registry));
        let roles = vec![admin, lab_role(), viewer_role(), operator_role()];
        let server = KccMcp::new(
            config,
            privacy,
            registry,
            workflow,
            jobs,
            poller,
            roles,
            fallback_role,
        );
        Ok(Self {
            directory,
            server,
            handle,
        })
    }

    pub(crate) async fn shutdown(self) -> Result<(), Box<dyn Error>> {
        let Self {
            directory,
            server: _,
            handle,
        } = self;
        handle.shutdown().await?;
        drop(directory);
        Ok(())
    }
}

pub(super) fn admin_role() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

pub(super) fn lab_role() -> Role {
    Role::new("lab".to_owned(), Permission::ALL, vec!["lab-*".to_owned()])
}

pub(super) fn viewer_role() -> Role {
    Role::new(
        "viewer".to_owned(),
        [Permission::Read],
        vec!["*".to_owned()],
    )
}

pub(super) fn operator_role() -> Role {
    Role::new(
        "operator".to_owned(),
        [
            Permission::Read,
            Permission::Write,
            Permission::Save,
            Permission::Migrate,
        ],
        vec!["*".to_owned()],
    )
}
