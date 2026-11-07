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
use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

use kcc_app::{
    accounts::{AccountStore, Clock, SystemClock},
    api_keys::api_key_entries,
    audit::AuditLog,
    backups::{BackupRetention, BackupStore},
    jobs::JobRunner,
    permissions::{Role, load_roles, rbac_config},
    persist::StateStore,
    poller::Poller,
    registry::RouterRegistry,
    secrets::{MasterKey, master_key_path},
    settings::{Config, default_config_dir},
    workflow::ChangeWorkflow,
};
use kcc_i18n::locale::Locale;
use kcc_mcp::KccMcp;
use kcc_migrate::presets::store::PresetStore;
use kcc_telemetry::{
    logs::runtime::Service as LogService,
    metrics::{instrumentation::SelfMetrics, service::MetricsExporter},
};
use kcc_web::{
    WebState, WebStateConfig,
    admin::{AdminServices, ServerFacts, TransportReload},
    fleet::{BackupServices, FleetServices},
    session::CookieSecurity,
    web_router,
};
use rmcp_server_kit::{
    auth::{AuthConfig, RateLimitConfig},
    metrics::McpMetrics,
    observability::init_tracing_from_config_strict,
    rbac::RbacPolicy,
    transport::{McpServerConfig, ReadinessCheck, serve, serve_stdio},
};
use serde_json::json;

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

/// Process outcome mapped to the todo-47 exit-code contract.
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
    let state_dir = config.state.resolved_dir().map_err(error)?;
    let state = StateStore::open(&state_dir).map_err(error)?;
    let _state_lock = state.try_lock("server").map_err(|source| {
        ServerError(format!(
            "cannot start kcc serve with state directory {}: another kcc serve holds the server lock ({source})",
            state_dir.display()
        ))
    })?;
    let mut services = Services::open(&config, state).await?;
    let handler = services.handler(&config, config.mcp.http_enabled)?;
    let rbac = Arc::new(RbacPolicy::new(&handler.rbac_config()));
    let auth = AuthConfig::with_keys(api_key_entries(&services.state).map_err(error)?)
        .with_rate_limit(RateLimitConfig::new(30).with_pre_auth_burst(10));
    let tls = config.server.tls_cert_path.is_some() && config.server.tls_key_path.is_some();
    let base = McpServerConfig::new("placeholder:0", "kcc", env!("CARGO_PKG_VERSION"));
    let readiness = readiness_check(services.state.dir().to_owned(), services.audit.clone());
    let mut server = config
        .server
        .apply_to_mcp_config(base)
        .map_err(error)?
        .with_auth(auth)
        .with_rbac(rbac)
        .with_extra_route_rate_limit(600)
        .with_security_headers(kcc_web::csp::security_headers(tls))
        .with_readiness_check(readiness);
    let auth_reload = Arc::new(TransportReload::new(
        services.state.clone(),
        handler.tool_specs().to_vec(),
    ));
    if config.web.enabled {
        let web_state = services.web_state(&config, tls, Arc::clone(&auth_reload))?;
        server = server.with_extra_router(web_router(web_state));
    }
    server = with_reload(
        server,
        auth_reload.slot(),
        path,
        Arc::clone(&services.registry),
        services.state.clone(),
        handler.tool_specs().to_vec(),
    );
    let (with_exporter, _exporter) = with_metrics(server, &config, &services).await?;
    server = with_exporter;
    let serve_result = serve(server.validate().map_err(error)?, move || handler.clone()).await;
    let drain = services.jobs.drain(Duration::from_secs(30)).await;
    tracing::info!(
        cancelled = drain.cancelled,
        still_running = drain.still_running,
        "jobs drained; any armed router fail-safe remains armed for rollback"
    );
    serve_result.map_err(error)?;
    if let Some(logs) = services.logs.take() {
        logs.shutdown().await;
    }
    Ok(Outcome::Ok)
}

/// Runs the local stdio MCP command.
// cancel-safe: rmcp owns stdio framing and the service future reaches terminal cleanup.
pub async fn run_stdio(config_path: Option<PathBuf>) -> Result<Outcome, ServerError> {
    let (_path, config, _tracing_guard) = load_config(config_path)?;
    if !config.mcp.stdio_enabled {
        tracing::error!("stdio transport is disabled by mcp.stdio_enabled");
        return Ok(Outcome::Forbidden);
    }
    let state = StateStore::open(&config.state.resolved_dir().map_err(error)?).map_err(error)?;
    let services = Services::open(&config, state).await?;
    let handler = services.handler(&config, true)?;
    serve_stdio(handler).await.map_err(error)?;
    let drain = services.jobs.drain(Duration::from_secs(30)).await;
    tracing::info!(
        cancelled = drain.cancelled,
        still_running = drain.still_running,
        "stdio jobs drained; any armed router fail-safe remains armed for rollback"
    );
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
    /// Built-in and custom application roles.
    roles: Vec<Role>,
    /// Shared wall clock.
    clock: Arc<dyn Clock>,
    /// Self-metrics, when `[metrics] enabled`.
    metrics: Option<Arc<SelfMetrics>>,
    /// Router log collectors and sink workers, when `[logs] enabled`.
    logs: Option<LogService>,
}

impl Services {
    /// Opens state and constructs each singleton service.
    // cancel-safe: startup performs local state opens and read-only router recovery inspection.
    async fn open(config: &Config, state: StateStore) -> Result<Self, ServerError> {
        let metrics = if config.metrics.enabled || config.logs.enabled {
            Some(SelfMetrics::new(env!("CARGO_PKG_VERSION")).map_err(error)?)
        } else {
            None
        };
        let mut profiles =
            RouterRegistry::new(state.clone(), &config.routers, &config.outbound).map_err(error)?;
        if let Some(self_metrics) = &metrics {
            profiles = profiles.with_rci_observers(self_metrics.rci_observers());
        }
        let registry = Arc::new(profiles);
        let poller = Poller::new(Arc::clone(&registry));
        let audit = AuditLog::spawn(&state).map_err(error)?;
        let roles = load_roles(&state).map_err(error)?;
        let key_path = master_key_path().map_err(error)?;
        let accounts_key = MasterKey::load_or_create(&key_path).map_err(error)?;
        let backup_key = MasterKey::load(&key_path).map_err(error)?;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
        let accounts = Arc::new(AccountStore::new(
            state.clone(),
            accounts_key,
            config.web.lockout,
            Arc::clone(&clock),
        ));
        let backups = Arc::new(BackupStore::new(state.clone(), backup_key).with_retention(
            BackupRetention::new(config.backups.max_age, config.backups.keep_last),
        ));
        let workflow = ChangeWorkflow::new(
            state.clone(),
            Arc::clone(&registry),
            Arc::clone(&backups),
            audit.clone(),
        );
        let jobs = JobRunner::open(state.clone(), Arc::clone(&registry))
            .await
            .map_err(error)?;
        let logs = if config.logs.enabled {
            let self_metrics = metrics
                .clone()
                .ok_or_else(|| ServerError("log metrics are unavailable".to_owned()))?;
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
            Some(
                LogService::start(routers, &config.logs, self_metrics)
                    .await
                    .map_err(error)?,
            )
        } else {
            None
        };
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
        let role = self
            .roles
            .iter()
            .find(|role| role.name == config.mcp.stdio_role)
            .cloned()
            .ok_or_else(|| {
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
            self.roles.clone(),
            role,
        )
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
        tls: bool,
        auth_reload: Arc<TransportReload>,
    ) -> Result<WebState, ServerError> {
        let default_locale = Locale::from_tag(&config.web.default_locale)
            .ok_or_else(|| ServerError("web.default_locale is unsupported".to_owned()))?;
        let cookie_security = if tls {
            CookieSecurity::Tls
        } else {
            CookieSecurity::LoopbackHttp
        };
        Ok(WebState::new(WebStateConfig {
            default_locale,
            accounts: Arc::clone(&self.accounts),
            audit: self.audit.clone(),
            roles: self.roles.clone(),
            session_idle: config.web.session_idle,
            session_absolute: config.web.session_absolute,
            allowed_origins: config.web_allowed_origins().map_err(error)?,
            cookie_security,
            clock: Arc::clone(&self.clock),
        })
        .with_fleet(FleetServices {
            registry: Arc::clone(&self.registry),
            poller: Arc::clone(&self.poller),
            workflow: Arc::clone(&self.workflow),
            credentials_dir: self.state.dir().join("router-credentials"),
            update_check: None,
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

/// Stores the transport's reload handle in `slot` for the Web UI's administration
/// pages, and wires Unix SIGHUP reload of API keys, RBAC, and router profiles.
#[cfg(unix)]
fn with_reload(
    config: McpServerConfig,
    slot: Arc<OnceLock<rmcp_server_kit::transport::ReloadHandle>>,
    path: PathBuf,
    registry: Arc<RouterRegistry>,
    state: StateStore,
    tools: Vec<kcc_app::permissions::ToolSpec>,
) -> McpServerConfig {
    config.with_reload_callback(move |handle| {
        if slot.set(handle).is_err() {
            tracing::error!("the MCP transport delivered a second reload handle; keeping the first");
        }
        drop(tokio::spawn(async move {
            let Some(installed) = slot.get() else { return; };
            let mut signals = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                Ok(signals) => signals,
                Err(error) => { tracing::error!(%error, "cannot install SIGHUP reload handler"); return; }
            };
            while signals.recv().await.is_some() {
                if let Err(error) = reload(installed, &path, &registry, &state, &tools).await {
                    tracing::error!(%error, "SIGHUP reload rejected; previous configuration remains active");
                }
            }
        }));
    })
}

/// Stores the transport's reload handle in `slot` for the Web UI's administration
/// pages; SIGHUP reload is unavailable on non-Unix platforms.
#[cfg(not(unix))]
fn with_reload(
    config: McpServerConfig,
    slot: Arc<OnceLock<rmcp_server_kit::transport::ReloadHandle>>,
    _path: PathBuf,
    _registry: Arc<RouterRegistry>,
    _state: StateStore,
    _tools: Vec<kcc_app::permissions::ToolSpec>,
) -> McpServerConfig {
    config.with_reload_callback(move |handle| {
        if slot.set(handle).is_err() {
            tracing::error!(
                "the MCP transport delivered a second reload handle; keeping the first"
            );
        }
    })
}

/// Applies one validated reload generation.
#[cfg(unix)]
async fn reload(
    handle: &rmcp_server_kit::transport::ReloadHandle,
    path: &Path,
    registry: &RouterRegistry,
    state: &StateStore,
    tools: &[kcc_app::permissions::ToolSpec],
) -> Result<(), ServerError> {
    let mut config = Config::load(path).map_err(error)?;
    drop(config.apply_env_overrides().map_err(error)?);
    config.validate().map_err(error)?;
    let roles = load_roles(state).map_err(error)?;
    let keys = api_key_entries(state).map_err(error)?;
    let invalidated = registry.reload(&config).await.map_err(error)?;
    handle.try_reload_auth_keys(keys).map_err(error)?;
    handle.reload_rbac(RbacPolicy::new(&rbac_config(&roles, tools)));
    tracing::info!(invalidated, "configuration reloaded from SIGHUP");
    Ok(())
}

/// Serves `/metrics` from the shared poller's cache when `[metrics] enabled`.
///
/// The kit listener is plaintext and unauthenticated by design; `Config::validate` already
/// refused ports below 1024 and a non-loopback bind without `allow_non_loopback`.
// cancel-safe: registers local poller subscriptions only; no router request is awaited.
async fn with_metrics(
    server: McpServerConfig,
    config: &Config,
    services: &Services,
) -> Result<(McpServerConfig, Option<MetricsExporter>), ServerError> {
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
    let exporter = MetricsExporter::new(
        Arc::clone(&services.poller),
        &config.metrics,
        Arc::clone(&self_metrics),
    )
    .map_err(error)?;
    exporter.register(&kit.registry).map_err(error)?;
    for entry in services.registry.list().map_err(error)? {
        exporter.watch(&entry.profile.id).await;
    }
    drop(self_metrics.track_jobs(Arc::clone(&services.jobs)));
    Ok((
        server
            .with_metrics(config.metrics.bind.to_string())
            .with_metrics_handle(kit),
        Some(exporter),
    ))
}

/// Converts a display-safe service error into the binary error surface.
fn error(source: impl core::fmt::Display) -> ServerError {
    ServerError(source.to_string())
}
