//! Router fleet services: the registry, the shared poller and the change workflow the
//! dashboard, the router forms and the live streams use.
//!
//! [`crate::WebState::with_fleet`] attaches them. Without them every fleet page renders a
//! localized "not configured" notice and the live streams answer `503`.

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, fmt, pin::Pin, time::Duration};

use kcc_app::{
    backups::BackupStore,
    credentials::CredentialStore,
    permissions::{Permission, Role},
    poller::Poller,
    registry::{self, RegistryEntry, RouterRegistry},
    settings::BackupsConfig,
    workflow::ChangeWorkflow,
};
use tokio::task::spawn_blocking;

use crate::telemetry::Telemetry;

/// How long a firmware-update check result stays valid.
pub const UPDATE_CHECK_TTL: Duration = Duration::from_hours(6);

/// The result of a firmware-update check for one router.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdateStatus {
    /// Newer firmware is available.
    Available {
        /// The version the router offers to install.
        version: String,
    },
    /// The router runs the newest firmware of its channel.
    Current,
    /// No check has completed.
    Unknown,
}

/// Checks a router for newer firmware, such as through its components check, and keeps
/// the results.
///
/// The check owns the cache: the fleet services show [`UpdateCheck::cached`] and start
/// [`UpdateCheck::check`] in the background whenever it says a check is due.
pub trait UpdateCheck: Send + Sync {
    /// Checks `router` for newer firmware, unless a check of it is not due.
    fn check<'call>(
        &'call self,
        router: &'call str,
    ) -> Pin<Box<dyn Future<Output = UpdateStatus> + Send + 'call>>;

    /// The latest result for `router` without asking it ([`UpdateStatus::Unknown`]
    /// before a check completed), and whether a check of it is due.
    fn cached(&self, router: &str) -> (UpdateStatus, bool);
}

/// The application services the fleet pages need.
#[expect(
    clippy::exhaustive_structs,
    reason = "application integration constructs the complete fleet wiring"
)]
#[expect(
    clippy::module_name_repetitions,
    reason = "integrators read it as `FleetServices` beside `WebStateConfig`"
)]
pub struct FleetServices {
    /// Merged router profiles and the shared client pool.
    pub registry: Arc<RouterRegistry>,
    /// The shared subscriber-driven poller.
    pub poller: Arc<Poller>,
    /// The leased write workflow used by Save.
    pub workflow: Arc<ChangeWorkflow>,
    /// Encrypted credentials of routers added in the Web UI.
    pub credentials: Arc<CredentialStore>,
    /// Firmware-update check; `None` shows the update status as unknown.
    pub update_check: Option<Arc<dyn UpdateCheck>>,
    /// The routers' encrypted configuration backups; `None` leaves the configuration page
    /// without its backups.
    pub backups: Option<BackupServices>,
}

/// The encrypted configuration backups the configuration page lists and creates, and the
/// retention `kcc.toml` sets for them.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BackupServices {
    /// The store the change workflow writes its automatic backups to.
    store: Arc<BackupStore>,
    /// The `[backups]` retention.
    retention: BackupsConfig,
}

impl BackupServices {
    /// The backups in `store`, kept as `retention` says.
    #[inline]
    #[must_use]
    pub const fn new(store: Arc<BackupStore>, retention: BackupsConfig) -> Self {
        Self { store, retention }
    }

    /// The encrypted backup store.
    pub(crate) const fn store(&self) -> &Arc<BackupStore> {
        &self.store
    }

    /// The retention `kcc.toml` sets.
    pub(crate) const fn retention(&self) -> BackupsConfig {
        self.retention
    }
}

impl fmt::Debug for FleetServices {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FleetServices")
            .field("registry", &self.registry)
            .field("credentials", &"CredentialStore([REDACTED])")
            .field("update_check", &self.update_check.is_some())
            .finish_non_exhaustive()
    }
}

/// Fleet services plus the Web UI's live state.
pub(crate) struct Fleet {
    /// Router profiles and clients.
    registry: Arc<RouterRegistry>,
    /// Change workflow for Save.
    workflow: Arc<ChangeWorkflow>,
    /// Encrypted credentials of Web UI routers.
    credentials: Arc<CredentialStore>,
    /// Per-router live feeds over the shared poller.
    telemetry: Telemetry,
    /// The firmware-update check, which keeps the results.
    updates: Option<Arc<dyn UpdateCheck>>,
    /// Encrypted configuration backups.
    backups: Option<BackupServices>,
}

impl Fleet {
    /// Builds the live state around `services`.
    pub(crate) fn new(services: FleetServices) -> Self {
        Self {
            telemetry: Telemetry::new(services.poller),
            updates: services.update_check,
            registry: services.registry,
            workflow: services.workflow,
            credentials: services.credentials,
            backups: services.backups,
        }
    }

    /// Encrypted configuration backups, when attached.
    pub(crate) const fn backups(&self) -> Option<&BackupServices> {
        self.backups.as_ref()
    }

    /// Router profiles and clients.
    pub(crate) const fn registry(&self) -> &Arc<RouterRegistry> {
        &self.registry
    }

    /// Change workflow for Save.
    pub(crate) const fn workflow(&self) -> &Arc<ChangeWorkflow> {
        &self.workflow
    }

    /// Encrypted credential store of Web UI routers.
    pub(crate) const fn credentials(&self) -> &Arc<CredentialStore> {
        &self.credentials
    }

    /// Per-router live feeds.
    pub(crate) const fn telemetry(&self) -> &Telemetry {
        &self.telemetry
    }

    /// The latest update status of `router`, starting a background check when due.
    pub(crate) fn update_status(&self, router: &str) -> UpdateStatus {
        let Some(check) = self.updates.as_ref() else {
            return UpdateStatus::Unknown;
        };
        let (status, due) = check.cached(router);
        if due {
            let checker = Arc::clone(check);
            let id = router.to_owned();
            drop(tokio::spawn(async move {
                drop(checker.check(&id).await);
            }));
        }
        status
    }

    /// Every profile `role` may read, in id order.
    ///
    /// # Errors
    ///
    /// Returns registry storage errors and a failed blocking task.
    // cancel-safe: the blocking read changes no state.
    pub(crate) async fn visible(
        &self,
        role: &Role,
    ) -> Result<Vec<RegistryEntry>, Box<dyn Error + Send + Sync>> {
        let registry = Arc::clone(&self.registry);
        let entries = spawn_blocking(move || registry.list()).await??;
        Ok(entries
            .into_iter()
            .filter(|entry| registry::authorize(role, Permission::Read, &entry.profile.id).is_ok())
            .collect())
    }
}
