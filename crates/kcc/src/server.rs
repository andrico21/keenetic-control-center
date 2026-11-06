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
    api_keys::api_key_entries,
    audit::AuditLog,
    backups::BackupStore,
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
use kcc_web::{
    WebState, WebStateConfig, fleet::FleetServices, session::CookieSecurity, web_router,
};
use rmcp_server_kit::{
    auth::{AuthConfig, RateLimitConfig},
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
    let services = Services::open(&config, state).await?;
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
    if config.web.enabled {
        let web_state = services.web_state(&config, tls)?;
        server = server.with_extra_router(web_router(web_state));
    }
    server = with_reload(
        server,
        path,
        Arc::clone(&services.registry),
        services.state.clone(),
        handler.tool_specs().to_vec(),
    );
    let serve_result = serve(server.validate().map_err(error)?, move || handler.clone()).await;
    let drain = services.jobs.drain(Duration::from_secs(30)).await;
    tracing::info!(
        cancelled = drain.cancelled,
        still_running = drain.still_running,
        "jobs drained; any armed router fail-safe remains armed for rollback"
    );
    serve_result.map_err(error)?;
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
    /// Built-in and custom application roles.
    roles: Vec<Role>,
    /// Shared wall clock.
    clock: Arc<dyn Clock>,
}

impl Services {
    /// Opens state and constructs each singleton service.
    // cancel-safe: startup performs local state opens and read-only router recovery inspection.
    async fn open(config: &Config, state: StateStore) -> Result<Self, ServerError> {
        let registry = Arc::new(
            RouterRegistry::new(state.clone(), &config.routers, &config.outbound).map_err(error)?,
        );
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
        let backups = Arc::new(BackupStore::new(state.clone(), backup_key));
        let workflow =
            ChangeWorkflow::new(state.clone(), Arc::clone(&registry), backups, audit.clone());
        let jobs = JobRunner::open(state.clone(), Arc::clone(&registry))
            .await
            .map_err(error)?;
        Ok(Self {
            state,
            registry,
            poller,
            jobs,
            audit,
            accounts,
            workflow,
            roles,
            clock,
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
        ))
    }

    /// Builds the authenticated Web UI around the same fleet services.
    fn web_state(&self, config: &Config, tls: bool) -> Result<WebState, ServerError> {
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

/// Wires Unix SIGHUP reload of API keys, RBAC, and router profiles.
#[cfg(unix)]
fn with_reload(
    config: McpServerConfig,
    path: PathBuf,
    registry: Arc<RouterRegistry>,
    state: StateStore,
    tools: Vec<kcc_app::permissions::ToolSpec>,
) -> McpServerConfig {
    config.with_reload_callback(move |handle| {
        drop(tokio::spawn(async move {
            let mut signals = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                Ok(signals) => signals,
                Err(error) => { tracing::error!(%error, "cannot install SIGHUP reload handler"); return; }
            };
            while signals.recv().await.is_some() {
                if let Err(error) = reload(&handle, &path, &registry, &state, &tools).await {
                    tracing::error!(%error, "SIGHUP reload rejected; previous configuration remains active");
                }
            }
        }));
    })
}

/// Leaves reload unavailable on non-Unix platforms.
#[cfg(not(unix))]
fn with_reload(
    config: McpServerConfig,
    _path: PathBuf,
    _registry: Arc<RouterRegistry>,
    _state: StateStore,
    _tools: Vec<kcc_app::permissions::ToolSpec>,
) -> McpServerConfig {
    config
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

/// Converts a display-safe service error into the binary error surface.
fn error(source: impl core::fmt::Display) -> ServerError {
    ServerError(source.to_string())
}
