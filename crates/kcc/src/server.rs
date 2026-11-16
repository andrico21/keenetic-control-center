//! Process-level assembly for HTTP and stdio MCP transports.
#![expect(
    clippy::absolute_paths,
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "binary assembly keeps fully qualified service names visible and exposes no hot-path API"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::path::{Path, PathBuf};

use kcc_app::{
    accounts::{AccountStore, Clock, SystemClock},
    api_key_use::KeyUseRecorder,
    api_keys::api_key_entries,
    audit::AuditLog,
    backups::{BackupRetention, BackupStore},
    credentials::CredentialStore,
    jobs::JobRunner,
    permissions::load_roles,
    persist::StateStore,
    poller::Poller,
    registry::RouterRegistry,
    role_source::RoleSource,
    secrets::{MasterKey, master_key_path},
    settings::{Config, default_config_dir},
    workflow::ChangeWorkflow,
};
use kcc_i18n::locale::Locale;
use kcc_mcp::KccMcp;
use kcc_migrate::presets::store::PresetStore;
use kcc_telemetry::{
    logs::runtime::Service as LogService,
    metrics::{
        instrumentation::SelfMetrics, registry_follow::follow_registry, service::MetricsExporter,
    },
};
use kcc_web::{
    WebState, WebStateConfig,
    admin::{AdminServices, ServerFacts, TransportReload},
    fleet::{BackupServices, FleetServices},
    fleet_updates::ComponentsUpdateCheck,
    session::CookieSecurity,
    web_router,
};
use rmcp_server_kit::{
    auth::{AuthConfig, RateLimitConfig},
    metrics::McpMetrics,
    observability::init_tracing_from_config_strict,
    rbac::RbacPolicy,
    transport::{McpServerConfig, ReadinessCheck, serve_stdio, serve_with_listener},
};
use serde_json::json;

use crate::state_watch::StateWatch;

/// Generic process failure.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the process-level error name is unambiguous at call sites"
)]
pub struct ServerError(String);

impl ServerError {
    /// Builds the forward-compatible command refusal used by the binary dispatcher.
    #[inline]
    #[must_use]
    pub fn unsupported_command() -> Self {
        Self("unsupported command in this build".to_owned())
    }
}

/// Process outcome mapped to the exit-code contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Outcome {
    /// Command completed successfully.
    Ok,
    /// Generic startup or runtime failure.
    Failed,
    /// A configured policy forbids the requested command.
    Forbidden,
}

/// Process role selecting which runtime-owned background services are started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServicesMode {
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

impl Outcome {
    /// Stable process exit code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Failed => 1,
            Self::Forbidden => 10,
        }
    }
}

/// Runs the HTTP server command.
// NOT cancel-safe: once the listener starts, shutdown must be driven cooperatively by the kit.
pub async fn run_serve(config_path: Option<PathBuf>) -> Result<Outcome, ServerError> {
    let (path, config, _tracing_guard) = load_config(config_path)?;
    crate::server_tls_key::check(&config)?;
    let state_dir = config.state.resolved_dir().map_err(error)?;
    let state = StateStore::open(&state_dir).map_err(error)?;
    let _state_lock = state.try_lock("server").map_err(|source| {
        ServerError(format!(
            "cannot start kcc serve with state directory {}: another kcc serve holds the server lock ({source})",
            state_dir.display()
        ))
    })?;
    let mut services = Services::open(&config, state, ServicesMode::Serve).await?;
    let handler = services.handler(&config, config.mcp.http_enabled)?;
    let rbac = Arc::new(RbacPolicy::new(&handler.rbac_config()));
    let auth = AuthConfig::with_keys(api_key_entries(&services.state).map_err(error)?)
        .with_rate_limit(RateLimitConfig::new(30).with_pre_auth_burst(10));
    let secure_transport = config.browser_transport_secure();
    let base = McpServerConfig::new("placeholder:0", "kcc", env!("CARGO_PKG_VERSION"));
    let readiness = readiness_check(services.state.dir().to_owned(), services.audit.clone());
    let server = config
        .server
        .apply_to_mcp_config(base)
        .map_err(error)?
        .with_auth(auth)
        .with_rbac(rbac)
        .with_extra_route_rate_limit(600)
        .with_security_headers(kcc_web::csp::security_headers(secure_transport))
        .with_readiness_check(readiness);
    let mut server_with_origins = crate::server_origins::apply(server, &config).map_err(error)?;
    let auth_reload = Arc::new(
        TransportReload::new(services.state.clone(), handler.tool_specs().to_vec())
            .with_role_source(services.roles.clone()),
    );
    let _updates = crate::server_tasks::refresh_updates(Arc::clone(&services.updates));
    let web_state = if config.web.enabled {
        Some(services.web_state(&config, Arc::clone(&auth_reload))?)
    } else {
        None
    };
    let _sessions = web_state.as_ref().and_then(|web| {
        let metrics = services.metrics.clone()?;
        Some(crate::server_tasks::track_sessions(web.clone(), metrics))
    });
    if let Some(web) = &web_state {
        server_with_origins = server_with_origins.with_extra_router(web_router(web.clone()));
    }
    server_with_origins = with_reload(
        server_with_origins,
        StateWatch::new(Arc::clone(&auth_reload), web_state),
        path,
        Arc::clone(&services.registry),
    );
    let (configured_server, _exporter) = with_metrics(server_with_origins, &config, &services)?;
    let validated = configured_server.validate().map_err(error)?;
    let listener = tokio::net::TcpListener::bind((
        config.server.listen_addr.trim_matches(['[', ']']),
        config.server.listen_port,
    ))
    .await
    .map_err(|source| {
        error(format!(
            "bind {}:{}: {source}",
            config.server.listen_addr, config.server.listen_port
        ))
    })?;
    #[expect(
        clippy::default_trait_access,
        reason = "the kit's `CancellationToken`, inferred from `serve_with_listener`, is not a dependency of this crate"
    )]
    let shutdown = Default::default();
    let serving = serve_with_listener(
        listener,
        validated,
        move || handler.clone(),
        None,
        Some(Clone::clone(&shutdown)),
    );
    let serve_result =
        crate::server_shutdown::serve_until_shutdown(serving, &services.audit, || {
            shutdown.cancel();
        })
        .await;
    crate::server_shutdown::wait_for_brackets(services.workflow.brackets()).await;
    let drain = services.jobs.drain(Duration::from_secs(30)).await;
    tracing::info!(
        cancelled = drain.cancelled,
        still_running = drain.still_running,
        "jobs drained; any armed router fail-safe remains armed for rollback"
    );
    crate::server_shutdown::flush_audit(&services.audit).await;
    serve_result?;
    if let Some(logs) = services.logs.take() {
        logs.shutdown().await;
    }
    Ok(Outcome::Ok)
}

/// Runs the local stdio MCP command.
///
/// Once stdin closes it waits, at most `BRACKET_GRACE`, for tool calls still closing a
/// router's safety bracket, then at most `AUDIT_FLUSH_WAIT` for the audit entries still
/// queued.
// cancel-safe: rmcp owns stdio framing, the service future reaches terminal cleanup and the
// bracket wait only observes the count.
pub async fn run_stdio(config_path: Option<PathBuf>) -> Result<Outcome, ServerError> {
    let (_path, config, _tracing_guard) = load_config(config_path)?;
    if !config.mcp.stdio_enabled {
        tracing::error!("stdio transport is disabled by mcp.stdio_enabled");
        return Ok(Outcome::Forbidden);
    }
    let state = StateStore::open(&config.state.resolved_dir().map_err(error)?).map_err(error)?;
    let services = Services::open(&config, state, ServicesMode::Stdio).await?;
    let handler = services.handler(&config, true)?;
    let served = serve_stdio(handler).await.map_err(error);
    crate::server_shutdown::wait_for_brackets(services.workflow.brackets()).await;
    if let Err(failure) = served {
        crate::server_shutdown::flush_audit(&services.audit).await;
        return Err(failure);
    }
    let drain = services.jobs.drain(Duration::from_secs(30)).await;
    tracing::info!(
        cancelled = drain.cancelled,
        still_running = drain.still_running,
        "stdio jobs drained; any armed router fail-safe remains armed for rollback"
    );
    crate::server_shutdown::flush_audit(&services.audit).await;
    Ok(Outcome::Ok)
}

/// Loads, overrides, traces, and validates one configuration generation.
fn load_config(
    config_path: Option<PathBuf>,
) -> Result<
    (
        PathBuf,
        Config,
        rmcp_server_kit::observability::TracingGuard,
    ),
    ServerError,
> {
    let path = resolve_config_path(config_path)?;
    let mut config = Config::load(&path).map_err(error)?;
    let overrides = config.apply_env_overrides().map_err(error)?;
    let tracing_guard = init_tracing_from_config_strict(&config.observability).map_err(error)?;
    crate::privileges::log_startup_posture();
    for entry in overrides {
        tracing::info!(env_var = %entry.env_var, target = %entry.target_field, "environment override applied");
    }
    config.validate().map_err(error)?;
    Ok((path, config, tracing_guard))
}

/// Long-lived application services shared by web and MCP handlers.
struct Services {
    /// Persistent state directory.
    state: StateStore,
    /// Router profiles and shared clients.
    registry: Arc<RouterRegistry>,
    /// Shared subscriber-driven poller.
    poller: Arc<Poller>,
    /// Persisted background jobs.
    jobs: Arc<JobRunner>,
    /// Tamper-evident audit writer.
    audit: AuditLog,
    /// Web account service.
    accounts: Arc<AccountStore>,
    /// Protected router change workflow.
    workflow: Arc<ChangeWorkflow>,
    /// Encrypted startup-configuration backups, shared with the workflow.
    backups: Arc<BackupStore>,
    /// Built-in and custom application roles, shared by MCP, the Web UI and reloads.
    roles: RoleSource,
    /// Shared wall clock.
    clock: Arc<dyn Clock>,
    /// Cached firmware-update checks.
    updates: Arc<ComponentsUpdateCheck>,
    /// Self-metrics, when `[metrics] enabled`.
    metrics: Option<Arc<SelfMetrics>>,
    /// Router log collectors and sink workers, when `[logs] enabled`.
    logs: Option<LogService>,
}

impl Services {
    /// Starts router log collectors and sink workers when `mode` owns them.
    // NOT cancel-safe: delegates to `LogService::start`.
    async fn start_logs(
        mode: ServicesMode,
        config: &Config,
        registry: &RouterRegistry,
        metrics: Option<Arc<SelfMetrics>>,
    ) -> Result<Option<LogService>, ServerError> {
        if !mode.starts_logs(config.logs.enabled) {
            return Ok(None);
        }
        let self_metrics =
            metrics.ok_or_else(|| ServerError("log metrics are unavailable".to_owned()))?;
        let mut routers = Vec::new();
        for entry in registry.list().map_err(error)? {
            if config.logs.routers.is_empty()
                || config
                    .logs
                    .routers
                    .iter()
                    .any(|router| router == &entry.profile.id)
            {
                let client = registry.client(&entry.profile.id).await.map_err(error)?;
                routers.push((entry.profile.id, client));
            }
        }
        LogService::start(routers, &config.logs, self_metrics)
            .await
            .map(Some)
            .map_err(error)
    }

    /// Opens state and constructs each singleton service.
    // cancel-safe: startup performs local state opens and read-only router recovery inspection.
    async fn open(
        config: &Config,
        state: StateStore,
        mode: ServicesMode,
    ) -> Result<Self, ServerError> {
        let starts_logs = mode.starts_logs(config.logs.enabled);
        let metrics = if config.metrics.enabled || starts_logs {
            Some(SelfMetrics::new(env!("CARGO_PKG_VERSION")).map_err(error)?)
        } else {
            None
        };
        let key_path = master_key_path().map_err(error)?;
        let master_key = MasterKey::load_or_create(&key_path).map_err(error)?;
        let credentials = Arc::new(CredentialStore::new(state.clone(), master_key.duplicate()));
        let migrations = credentials.migrate_all().map_err(error)?;
        let mut profiles = RouterRegistry::new(state.clone(), &config.routers, &config.outbound)
            .map_err(error)?
            .with_credentials(Arc::clone(&credentials));
        if let Some(self_metrics) = &metrics {
            profiles = profiles.with_rci_observers(self_metrics.rci_observers());
        }
        let registry = Arc::new(profiles);
        crate::server_migrations::warn_external_password_files(&registry).map_err(error)?;
        crate::server_outbound::warn_closed_policy(
            &config.outbound,
            registry.list().map_err(error)?.len(),
        );
        let poller = Poller::new(Arc::clone(&registry));
        let audit = AuditLog::spawn_with_policy(
            &state,
            kcc_app::audit::AuditPolicy::default().with_retention(config.audit.retention),
        )
        .map_err(error)?;
        crate::server_migrations::append_credential_events(&audit, migrations, "startup")
            .await
            .map_err(error)?;
        let roles = RoleSource::new(load_roles(&state).map_err(error)?);
        let accounts_key = master_key.duplicate();
        let backup_key = MasterKey::load(&key_path).map_err(error)?;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
        let accounts = Arc::new(
            AccountStore::new(
                state.clone(),
                accounts_key,
                config.web.lockout,
                Arc::clone(&clock),
            )
            .with_max_failures(config.web.login_max_failures),
        );
        let backups = Arc::new(BackupStore::new(state.clone(), backup_key).with_retention(
            BackupRetention::new(config.backups.max_age, config.backups.keep_last),
        ));
        let workflow = ChangeWorkflow::new(
            state.clone(),
            Arc::clone(&registry),
            Arc::clone(&backups),
            audit.clone(),
        );
        let jobs = JobRunner::open(state.clone(), Arc::clone(&registry), audit.clone())
            .await
            .map_err(error)?;
        let logs = Self::start_logs(mode, config, &registry, metrics.clone()).await?;
        let updates = Arc::new(ComponentsUpdateCheck::new(
            Arc::clone(&registry),
            Arc::clone(&poller),
            Arc::clone(&clock),
        ));
        Ok(Self {
            state,
            registry,
            poller,
            jobs,
            audit,
            accounts,
            workflow,
            backups,
            roles,
            clock,
            updates,
            metrics,
            logs,
        })
    }

    /// Builds an MCP handler and resolves its local fallback role.
    fn handler(&self, config: &Config, enabled: bool) -> Result<KccMcp, ServerError> {
        let mut mcp = config.mcp.clone();
        if !enabled {
            mcp.toolsets.clear();
        }
        let role = self.roles.find(&config.mcp.stdio_role).ok_or_else(|| {
            ServerError(format!(
                "configured stdio role {:?} does not exist",
                config.mcp.stdio_role
            ))
        })?;
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
        .with_presets(PresetStore::new(
            self.state.clone(),
            MasterKey::load(&master_key_path().map_err(error)?).map_err(error)?,
        )))
    }

    /// Builds the authenticated Web UI around the same fleet services; administration
    /// changes reach the running MCP transport through `auth_reload`.
    fn web_state(
        &self,
        config: &Config,
        auth_reload: Arc<TransportReload>,
    ) -> Result<WebState, ServerError> {
        let default_locale = Locale::from_tag(&config.web.default_locale)
            .ok_or_else(|| ServerError("web.default_locale is unsupported".to_owned()))?;
        let update_check: Arc<dyn kcc_web::fleet::UpdateCheck> =
            Arc::<ComponentsUpdateCheck>::clone(&self.updates);
        let cookie_security = if config.browser_transport_secure() {
            CookieSecurity::Tls
        } else {
            CookieSecurity::LoopbackHttp
        };
        Ok(WebState::new(WebStateConfig {
            default_locale,
            accounts: Arc::clone(&self.accounts),
            audit: self.audit.clone(),
            roles: self.roles.current().to_vec(),
            session_idle: config.web.session_idle,
            session_absolute: config.web.session_absolute,
            allowed_origins: config.web_allowed_origins().map_err(error)?,
            cookie_security,
            clock: Arc::clone(&self.clock),
        })
        .with_role_source(self.roles.clone())
        .with_log_feeds(self.logs.as_ref().map_or_default(LogService::feeds))
        .with_fleet(FleetServices {
            registry: Arc::clone(&self.registry),
            poller: Arc::clone(&self.poller),
            workflow: Arc::clone(&self.workflow),
            credentials: Arc::new(CredentialStore::new(
                self.state.clone(),
                MasterKey::load(&master_key_path().map_err(error)?).map_err(error)?,
            )),
            update_check: Some(update_check),
            backups: Some(BackupServices::new(
                Arc::clone(&self.backups),
                config.backups,
            )),
        })
        .with_jobs(Arc::clone(&self.jobs))
        .with_admin(AdminServices {
            state: self.state.clone(),
            reload: Some(auth_reload),
            server: ServerFacts::from_config(env!("CARGO_PKG_VERSION").to_owned(), config),
        }))
    }
}

/// Resolves the explicit path or the platform default `kcc.toml`.
fn resolve_config_path(path: Option<PathBuf>) -> Result<PathBuf, ServerError> {
    path.or_else(|| default_config_dir().map(|directory| directory.join("kcc.toml")))
        .ok_or_else(|| ServerError("no config path and no platform config directory".to_owned()))
}

/// Builds the state-directory and audit-writer readiness probe.
fn readiness_check(state_dir: PathBuf, audit: AuditLog) -> ReadinessCheck {
    Arc::new(move || {
        let path = state_dir.join(".ready");
        let audit_alive = audit.is_alive();
        Box::pin(async move {
            let writable = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
                .is_ok();
            json!({ "ready": writable && audit_alive, "state_writable": writable, "audit_alive": audit_alive })
        })
    })
}

/// Hands the transport's reload handle to the Web UI and starts `watch` with SIGHUP.
///
/// The handle goes to the slot of `watch`'s transport, for the administration pages;
/// `watch` applies key and account changes made outside the server. A SIGHUP applies
/// the API keys and accounts as the watcher does, then reloads the roles (MCP RBAC, the
/// MCP handlers and the Web UI) and the router profiles.
#[cfg(unix)]
fn with_reload(
    config: McpServerConfig,
    watch: StateWatch,
    path: PathBuf,
    registry: Arc<RouterRegistry>,
) -> McpServerConfig {
    let slot = watch.transport().slot();
    let auth = Arc::clone(watch.transport());
    config.with_reload_callback(move |handle| {
        if slot.set(handle).is_err() {
            tracing::error!("the MCP transport delivered a second reload handle; keeping the first");
        }
        drop(tokio::spawn(watch.run(move || {
            let (transport, file, routers) =
                (Arc::clone(&auth), path.clone(), Arc::clone(&registry));
            async move {
                if let Err(error) = reload(&transport, &file, &routers).await {
                    tracing::error!(%error, "SIGHUP reload rejected; previous configuration remains active");
                }
            }
        })));
    })
}

/// Hands the transport's reload handle to the Web UI and starts `watch`.
///
/// SIGHUP reload is unavailable on non-Unix platforms.
#[cfg(not(unix))]
fn with_reload(
    config: McpServerConfig,
    watch: StateWatch,
    _path: PathBuf,
    _registry: Arc<RouterRegistry>,
) -> McpServerConfig {
    let slot = watch.transport().slot();
    config.with_reload_callback(move |handle| {
        if slot.set(handle).is_err() {
            tracing::error!(
                "the MCP transport delivered a second reload handle; keeping the first"
            );
        }
        drop(tokio::spawn(watch.run()));
    })
}

/// Applies one validated reload generation of `kcc.toml` and the roles.
// NOT cancel-safe: the router profiles may be replaced before the roles.
#[cfg(unix)]
async fn reload(
    auth: &TransportReload,
    path: &Path,
    registry: &RouterRegistry,
) -> Result<(), ServerError> {
    let mut config = Config::load(path).map_err(error)?;
    drop(config.apply_env_overrides().map_err(error)?);
    config.validate().map_err(error)?;
    let roles = load_roles(auth.state()).map_err(error)?;
    let invalidated = registry.reload(&config).await.map_err(error)?;
    auth.install_roles(roles).map_err(error)?;
    tracing::info!(invalidated, "configuration reloaded from SIGHUP");
    Ok(())
}

/// Serves `/metrics` from the shared poller's cache when `[metrics] enabled`.
///
/// The kit listener is plaintext and unauthenticated by design; `Config::validate` already
/// refused ports below 1024 and a non-loopback bind without `allow_non_loopback`.
// cancel-safe: synchronous; the registry follower registers the poller subscriptions.
fn with_metrics(
    server: McpServerConfig,
    config: &Config,
    services: &Services,
) -> Result<(McpServerConfig, Option<Arc<MetricsExporter>>), ServerError> {
    if !config.metrics.enabled {
        return Ok((server, None));
    }
    let Some(self_metrics) = services.metrics.clone() else {
        return Ok((server, None));
    };
    if !config.metrics.bind.ip().is_loopback() {
        tracing::warn!(bind = %config.metrics.bind, "unauthenticated metrics listener bound beyond loopback");
    }
    let kit = Arc::new(McpMetrics::new().map_err(error)?);
    let exporter = Arc::new(
        MetricsExporter::new(
            Arc::clone(&services.poller),
            &config.metrics,
            Arc::clone(&self_metrics),
        )
        .map_err(error)?,
    );
    exporter.register(&kit.registry).map_err(error)?;
    drop(follow_registry(
        Arc::clone(&exporter),
        Arc::clone(&services.registry),
    ));
    drop(self_metrics.track_jobs(Arc::clone(&services.jobs)));
    Ok((
        server
            .with_metrics(config.metrics.bind.to_string())
            .with_metrics_handle(kit),
        Some(exporter),
    ))
}

/// Converts a display-safe service error into the binary error surface.
pub(crate) fn error(source: impl core::fmt::Display) -> ServerError {
    ServerError(source.to_string())
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
