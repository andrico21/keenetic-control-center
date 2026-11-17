//! The composition root every kcc process shares: the master key, router credentials and
//! profiles, the audit writer, backups and the change workflow, each built once.
//!
//! `kcc serve`, `kcc mcp stdio` and every CLI command open the same [`Core`]; the
//! processes add only what their surface needs (polling, jobs, accounts, the Web UI).

extern crate alloc;

use alloc::sync::Arc;
use core::fmt;

use crate::{
    accounts::{Clock as _, SystemClock},
    audit::{Actor, ActorKind, AuditError, AuditEvent, AuditLog, AuditPolicy, request_id},
    backups::{BackupRetention, BackupStore},
    credentials::{CredentialError, CredentialStore, MigrationState},
    persist::StateStore,
    registry::{RciObserverFactory, RegistryError, RouterRegistry},
    secrets::{CryptoError, MasterKey, master_key_path},
    settings::Config,
    workflow::ChangeWorkflow,
};

/// What [`Core::open`] needs besides the state directory.
#[non_exhaustive]
pub struct CoreSetup<'config> {
    /// The loaded configuration.
    config: &'config Config,
    /// The request-id prefix of credential-migration audit events: `startup` for the
    /// servers, `cli` for a CLI run.
    origin: &'static str,
    /// Observers of every router request, when self-metrics are on.
    observers: Option<RciObserverFactory>,
}

impl fmt::Debug for CoreSetup<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreSetup")
            .field("origin", &self.origin)
            .field("observed", &self.observers.is_some())
            .finish_non_exhaustive()
    }
}

impl<'config> CoreSetup<'config> {
    /// A setup for `config` whose migration events carry request ids from `origin`.
    #[inline]
    #[must_use]
    pub const fn new(config: &'config Config, origin: &'static str) -> Self {
        Self {
            config,
            origin,
            observers: None,
        }
    }

    /// Observes every router request through `factory`.
    #[inline]
    #[must_use]
    pub fn with_rci_observers(mut self, factory: RciObserverFactory) -> Self {
        self.observers = Some(factory);
        self
    }
}

/// The services one process builds once and shares.
#[derive(Debug)]
#[non_exhaustive]
pub struct Core {
    /// The master key, loaded once; consumers take a [`MasterKey::duplicate`].
    pub key: MasterKey,
    /// Encrypted kcc-managed router credentials.
    pub credentials: Arc<CredentialStore>,
    /// Router profiles and shared clients.
    pub registry: Arc<RouterRegistry>,
    /// The tamper-evident audit writer.
    pub audit: AuditLog,
    /// Encrypted startup-configuration backups, shared with the workflow.
    pub backups: Arc<BackupStore>,
    /// The protected router change workflow.
    pub workflow: Arc<ChangeWorkflow>,
}

/// Why [`Core::open`] failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CoreError {
    /// The master key could not be located, read or created.
    #[error("{0}")]
    Key(#[source] CryptoError),
    /// A stored router credential could not be migrated.
    #[error("{0}")]
    Credentials(#[source] CredentialError),
    /// The router profiles could not be loaded.
    #[error("{0}")]
    Registry(#[source] RegistryError),
    /// The audit writer could not start or record a credential migration.
    #[error("{0}")]
    Audit(#[source] AuditError),
}

impl Core {
    /// Loads the master key once, migrates stored router credentials, loads the router
    /// profiles, starts the audit writer (recording each migrated credential by router
    /// id), and builds the backup store and the change workflow. Contacts no router.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Key`] when the master key cannot be located, read or created,
    /// [`CoreError::Credentials`] when a stored credential cannot be migrated,
    /// [`CoreError::Registry`] when the router profiles cannot be loaded, and
    /// [`CoreError::Audit`] when the audit writer cannot start or append a migration
    /// event.
    // NOT cancel-safe: a migration audit event may be appended after cancellation.
    #[inline]
    pub async fn open(state: StateStore, setup: CoreSetup<'_>) -> Result<Self, CoreError> {
        let config = setup.config;
        let key = master_key_path()
            .and_then(|path| MasterKey::load_or_create(&path))
            .map_err(CoreError::Key)?;
        let credentials = Arc::new(CredentialStore::new(state.clone(), key.duplicate()));
        let migrations = credentials.migrate_all().map_err(CoreError::Credentials)?;
        let mut profiles = RouterRegistry::new(state.clone(), &config.routers, &config.outbound)
            .map_err(CoreError::Registry)?
            .with_credentials(Arc::clone(&credentials));
        if let Some(factory) = setup.observers {
            profiles = profiles.with_rci_observers(factory);
        }
        let registry = Arc::new(profiles);
        let audit = AuditLog::spawn_with_policy(
            &state,
            AuditPolicy::default().with_retention(config.audit.retention),
        )
        .map_err(CoreError::Audit)?;
        append_migrations(&audit, migrations, setup.origin)
            .await
            .map_err(CoreError::Audit)?;
        let retention = BackupRetention::new(config.backups.max_age, config.backups.keep_last);
        let backups =
            Arc::new(BackupStore::new(state.clone(), key.duplicate()).with_retention(retention));
        let workflow = ChangeWorkflow::new(
            state,
            Arc::clone(&registry),
            Arc::clone(&backups),
            audit.clone(),
        );
        Ok(Self {
            key,
            credentials,
            registry,
            audit,
            backups,
            workflow,
        })
    }
}

/// Appends one audit event, naming only the router id, for each credential migrated
/// while the state was opened.
///
/// # Errors
///
/// Returns the audit writer's error when an event cannot be appended.
// NOT cancel-safe: an event may be appended after cancellation while awaiting acknowledgement.
async fn append_migrations(
    audit: &AuditLog,
    migrations: Vec<(String, MigrationState)>,
    origin: &str,
) -> Result<(), AuditError> {
    for (router, migration) in migrations {
        if !matches!(migration, MigrationState::Current) {
            let event = AuditEvent::new(
                SystemClock::default().unix_seconds(),
                Actor::new(ActorKind::System, "system".to_owned()),
                "router.credential_migrated".to_owned(),
            )
            .with_router(router)
            .with_result("success".to_owned(), request_id::next(origin));
            drop(audit.append(event).await?);
        }
    }
    Ok(())
}
