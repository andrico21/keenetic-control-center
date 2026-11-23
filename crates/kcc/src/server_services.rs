//! The long-lived services one server process builds: the shared core, polling, jobs,
//! accounts, roles and router logs, and the MCP handler built on them.
#![expect(
    clippy::field_scoped_visibility_modifiers,
    clippy::missing_errors_doc,
    reason = "binary assembly: `server` drives these services' fields directly and exposes no API"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{
    accounts::{AccountStore, Clock, SystemClock},
    api_key_use::KeyUseRecorder,
    audit::AuditLog,
    backups::BackupStore,
    composition::{Core, CoreSetup},
    credentials::CredentialStore,
    jobs::JobRunner,
    permissions::load_roles,
    persist::StateStore,
    poller::Poller,
    registry::RouterRegistry,
    role_source::RoleSource,
    secrets::MasterKey,
    settings::{Config, McpConfig},
    workflow::ChangeWorkflow,
};
use kcc_domain::entware::ssh::SshServices;
use kcc_mcp::KccMcp;
use kcc_migrate::presets::store::PresetStore;
use kcc_telemetry::{logs::runtime::Service as LogService, metrics::instrumentation::SelfMetrics};
use kcc_web::fleet_updates::ComponentsUpdateCheck;

use crate::{
    server_error::ServerError, server_mcp_auth::principals::FilePrincipals,
    server_migrations::warn_external_password_files, server_outbound::warn_closed_policy,
};

/// How long one MCP Entware SSH read may wait, for example behind a mutation that holds
/// the router's SSH session.
const ENTWARE_READ_LIMIT: Duration = Duration::from_secs(90);

/// Process role selecting which runtime-owned background services are started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServicesMode {
    /// Long-running HTTP daemon.
    Serve,
    /// Short-lived local MCP transport.
    Stdio,
}

impl ServicesMode {
    /// Whether this role owns router-log collection and sink workers.
    const fn starts_logs(self, logs_enabled: bool) -> bool {
        match self {
            Self::Serve => logs_enabled,
            Self::Stdio => false,
        }
    }
}

/// Long-lived application services shared by web and MCP handlers.
pub(crate) struct Services {
    /// Persistent state directory.
    pub(crate) state: StateStore,
    /// The master key, loaded once.
    pub(crate) key: MasterKey,
    /// Encrypted kcc-managed router credentials.
    pub(crate) credentials: Arc<CredentialStore>,
    /// Router profiles and shared clients.
    pub(crate) registry: Arc<RouterRegistry>,
    /// Shared subscriber-driven poller.
    pub(crate) poller: Arc<Poller>,
    /// Persisted background jobs.
    pub(crate) jobs: Arc<JobRunner>,
    /// Tamper-evident audit writer.
    pub(crate) audit: AuditLog,
    /// Web account service.
    pub(crate) accounts: Arc<AccountStore>,
    /// Protected router change workflow.
    pub(crate) workflow: Arc<ChangeWorkflow>,
    /// Encrypted startup-configuration backups, shared with the workflow.
    pub(crate) backups: Arc<BackupStore>,
    /// Built-in and custom application roles, shared by MCP, the Web UI and reloads.
    pub(crate) roles: RoleSource,
    /// Shared wall clock.
    pub(crate) clock: Arc<dyn Clock>,
    /// Cached firmware-update checks.
    pub(crate) updates: Arc<ComponentsUpdateCheck>,
    /// Self-metrics, when `[metrics] enabled`.
    pub(crate) metrics: Option<Arc<SelfMetrics>>,
    /// Router log collectors and sink workers, when `[logs] enabled`.
    pub(crate) logs: Option<LogService>,
    /// Entware SSH services: one session pool and the sealed SSH state, shared by every
    /// surface.
    pub(crate) entware_ssh: Arc<SshServices>,
}

impl Services {
    /// Starts router log collectors and sink workers when `mode` owns them.
    // NOT cancel-safe: delegates to `LogService::start`.
    pub(crate) async fn start_logs(
        mode: ServicesMode,
        config: &Config,
        registry: &RouterRegistry,
        metrics: Option<Arc<SelfMetrics>>,
    ) -> Result<Option<LogService>, ServerError> {
        if !mode.starts_logs(config.logs.enabled) {
            return Ok(None);
        }
        let self_metrics = metrics.ok_or(ServerError::LogMetricsUnavailable)?;
        let mut routers = Vec::new();
        for entry in registry.list()? {
            if config.logs.routers.is_empty()
                || config
                    .logs
                    .routers
                    .iter()
                    .any(|router| router == &entry.profile.id)
            {
                let client = registry.client(&entry.profile.id).await?;
                routers.push((entry.profile.id, client));
            }
        }
        Ok(Some(
            LogService::start(routers, &config.logs, self_metrics).await?,
        ))
    }

    /// Opens the shared core and constructs each singleton service.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, startup performs local state opens and read-only router
    // recovery inspection.
    pub(crate) async fn open(
        config: &Config,
        state: StateStore,
        mode: ServicesMode,
    ) -> Result<Self, ServerError> {
        let starts_logs = mode.starts_logs(config.logs.enabled);
        let metrics = if config.metrics.enabled || starts_logs {
            Some(SelfMetrics::new(env!("CARGO_PKG_VERSION"))?)
        } else {
            None
        };
        let mut setup = CoreSetup::new(config, "startup");
        if let Some(self_metrics) = &metrics {
            setup = setup.with_rci_observers(self_metrics.rci_observers());
        }
        let core = Core::open(state.clone(), setup).await?;
        warn_external_password_files(&core.registry)?;
        warn_closed_policy(&config.outbound, core.registry.list()?.len());
        let poller = Poller::new(Arc::clone(&core.registry));
        let roles = RoleSource::new(load_roles(&state)?);
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
        let accounts = Arc::new(
            AccountStore::new(
                state.clone(),
                core.key.duplicate(),
                config.web.lockout,
                Arc::clone(&clock),
            )
            .with_max_failures(config.web.login_max_failures),
        );
        let jobs = JobRunner::open(
            state.clone(),
            Arc::clone(&core.registry),
            core.audit.clone(),
        )
        .await?;
        let logs = Self::start_logs(mode, config, &core.registry, metrics.clone()).await?;
        let entware_ssh = Arc::new(SshServices::new(
            Arc::clone(&core.workflow),
            Arc::clone(&core.registry),
            core.audit.clone(),
            &core.key,
            Arc::clone(&clock),
        ));
        let updates = Arc::new(ComponentsUpdateCheck::new(
            Arc::clone(&core.registry),
            Arc::clone(&poller),
            Arc::clone(&clock),
        ));
        Ok(Self {
            state,
            key: core.key,
            credentials: core.credentials,
            registry: core.registry,
            poller,
            jobs,
            audit: core.audit,
            accounts,
            workflow: core.workflow,
            backups: core.backups,
            roles,
            clock,
            updates,
            metrics,
            logs,
            entware_ssh,
        })
    }

    /// Builds an MCP handler on the effective MCP settings `settings` and resolves its
    /// local fallback role.
    pub(crate) fn handler(
        &self,
        config: &Config,
        settings: &McpConfig,
        enabled: bool,
    ) -> Result<KccMcp, ServerError> {
        let mut mcp = settings.clone();
        if !enabled {
            mcp.toolsets.clear();
        }
        let role = self
            .roles
            .find(&settings.stdio_role)
            .ok_or_else(|| ServerError::UnknownStdioRole(settings.stdio_role.clone()))?;
        Ok(KccMcp::new(
            mcp,
            config.privacy,
            Arc::clone(&self.registry),
            Arc::clone(&self.workflow),
            Arc::clone(&self.jobs),
            Arc::clone(&self.poller),
            self.roles.current().to_vec(),
            role,
        )
        .with_role_source(self.roles.clone())
        .with_key_use(Arc::new(KeyUseRecorder::new(
            self.state.clone(),
            Arc::clone(&self.clock),
        )))
        .with_audit(self.audit.clone())
        .with_principals(Arc::new(FilePrincipals::new(
            Arc::clone(&self.accounts),
            self.state.clone(),
        )))
        .with_presets(PresetStore::new(self.state.clone(), self.key.duplicate()))
        .with_entware_ssh(Arc::clone(&self.entware_ssh), ENTWARE_READ_LIMIT))
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::error::Error;

    use kcc_app::{persist::StateStore, registry::RouterRegistry, settings::Config};
    use kcc_telemetry::metrics::instrumentation::SelfMetrics;

    use super::{Arc, Services, ServicesMode};

    /// Only the daemon role starts log collection, through the real startup path.
    #[tokio::test]
    async fn only_serve_mode_starts_router_logs() -> Result<(), Box<dyn Error>> {
        let config = Config::from_toml_str("[logs]\nenabled = true\n")?;
        let dir = tempfile::TempDir::new()?;
        let state = StateStore::open(dir.path())?;
        let registry = RouterRegistry::new(state, &config.routers, &config.outbound)?;
        let metrics = SelfMetrics::new("test")?;

        let stdio = Services::start_logs(
            ServicesMode::Stdio,
            &config,
            &registry,
            Some(Arc::clone(&metrics)),
        )
        .await?;
        if let Some(started) = stdio {
            started.shutdown().await;
            return Err("stdio must not start router logs".into());
        }

        let serve =
            Services::start_logs(ServicesMode::Serve, &config, &registry, Some(metrics)).await?;
        let service = serve.ok_or("serve must start router logs")?;
        service.shutdown().await;
        Ok(())
    }
}
