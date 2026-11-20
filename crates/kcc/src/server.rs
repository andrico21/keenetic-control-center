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
use std::path::PathBuf;

use kcc_app::{
    api_keys::api_key_entries,
    audit::AuditLog,
    persist::StateStore,
    settings::{Config, default_config_dir},
};
use kcc_web::{admin::TransportReload, web_router};
use rmcp_server_kit::{
    auth::{AuthConfig, RateLimitConfig},
    observability::init_tracing_from_config_strict,
    rbac::RbacPolicy,
    transport::{McpServerConfig, ReadinessCheck, serve_stdio, serve_with_listener},
};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::{
    server_error::{Outcome, ServerError},
    server_metrics::with_metrics,
    server_notify::{self, Deps, NotifyHandle, Options},
    server_reload::{hangups, with_reload},
    server_schedules::{self, wiring::start_for_server},
    server_services::{Services, ServicesMode},
    server_shutdown::BRACKET_GRACE,
    server_web::web_state,
    state_watch::StateWatch,
};

/// Runs the HTTP server command.
// NOT cancel-safe: once the listener starts, shutdown must be driven cooperatively by the kit.
pub async fn run_serve(config_path: Option<PathBuf>) -> Result<Outcome, ServerError> {
    let hangups = hangups();
    let (path, config, _tracing_guard) = load_config(config_path)?;
    crate::server_tls_key::check(&config)?;
    let state_dir = config.state.resolved_dir()?;
    let state = StateStore::open(&state_dir)?;
    let _state_lock = state
        .try_lock("server")
        .map_err(|source| ServerError::ServerLock {
            dir: state_dir.clone(),
            source,
        })?;
    let mut services = Services::open(&config, state, ServicesMode::Serve).await?;
    let notify = NotifyHandle::start(
        Deps::from_services(&services),
        Options::from_config(&config)?,
    )
    .await?;
    let scheduler = start_for_server(&services, &notify, &config);
    let handler = services.handler(&config, config.mcp.http_enabled)?;
    let rbac = Arc::new(RbacPolicy::new(&handler.rbac_config()));
    let auth = AuthConfig::with_keys(api_key_entries(&services.state)?)
        .with_rate_limit(RateLimitConfig::new(30).with_pre_auth_burst(10));
    let secure_transport = config.browser_transport_secure();
    let base = McpServerConfig::new("placeholder:0", "kcc", env!("CARGO_PKG_VERSION"));
    let readiness = readiness_check(services.state.dir().to_owned(), services.audit.clone());
    let server = config
        .server
        .apply_to_mcp_config(base)?
        .with_auth(auth)
        .with_rbac(rbac)
        .with_extra_route_rate_limit(600)
        .with_security_headers(kcc_web::csp::security_headers(secure_transport))
        .with_readiness_check(readiness);
    let mut server_with_origins = crate::server_origins::apply(server, &config)?;
    let auth_reload = Arc::new(
        TransportReload::new(services.state.clone(), handler.tool_specs().to_vec())
            .with_role_source(services.roles.clone()),
    );
    let updates = crate::server_tasks::refresh_updates(Arc::clone(&services.updates));
    let web_state = if config.web.enabled {
        Some(web_state(
            &services,
            &config,
            Arc::clone(&auth_reload),
            Arc::new(notify.clone()),
        )?)
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
        StateWatch::new(Arc::clone(&auth_reload), web_state)
            .with_follower(server_notify::FILES, notify.follower())
            .with_follower(server_schedules::FILES, scheduler.follower()),
        hangups,
        (path, Arc::clone(&services.registry)),
    );
    let (configured_server, _exporter) = with_metrics(&services, server_with_origins, &config)?;
    let validated = configured_server.validate()?;
    let listener = tokio::net::TcpListener::bind((
        config.server.listen_addr.trim_matches(['[', ']']),
        config.server.listen_port,
    ))
    .await
    .map_err(|source| ServerError::Bind {
        address: config.server.listen_addr.clone(),
        port: config.server.listen_port,
        source,
    })?;
    let shutdown = CancellationToken::new();
    let serving = serve_with_listener(
        listener,
        validated,
        move || handler.clone(),
        None,
        Some(shutdown.clone()),
    );
    let serve_result =
        crate::server_shutdown::serve_until_shutdown(serving, &services.audit, || {
            shutdown.cancel();
            scheduler.stop_token().cancel();
        })
        .await;
    scheduler.finish(BRACKET_GRACE).await;
    if !services.audit.is_alive() {
        notify.writer_stopped();
    }
    updates.abort();
    wind_down(&mut services, &notify).await;
    serve_result?;
    Ok(Outcome::Ok)
}

/// Stops `kcc serve`'s services once the listener and the scheduler have stopped.
///
/// Requests and scheduled runs closing a safety bracket get their grace, the jobs are
/// drained, the queued notifications get theirs, the audit entries are flushed, and the
/// router sessions and log collectors end.
// NOT cancel-safe: dropped midway, later steps never run and entries or lines queued for
// them are lost.
async fn wind_down(services: &mut Services, notify: &NotifyHandle) {
    crate::server_shutdown::wait_for_brackets(services.workflow.brackets()).await;
    let drain = services.jobs.drain(Duration::from_secs(30)).await;
    tracing::info!(
        cancelled = drain.cancelled,
        still_running = drain.still_running,
        "jobs drained; any armed router fail-safe remains armed for rollback"
    );
    notify.stop().await;
    crate::server_shutdown::flush_audit(&services.audit).await;
    services.registry.shutdown().await;
    if let Some(logs) = services.logs.take() {
        logs.shutdown().await;
    }
}

/// Runs the local stdio MCP command.
///
/// Once stdin closes, or on SIGTERM or SIGINT (which stop reading stdin; a tool call in
/// flight runs on), it waits, at most `BRACKET_GRACE`, for tool calls still closing a
/// router's safety bracket, then drains the jobs and gives at most `AUDIT_FLUSH_WAIT` to
/// the audit entries still queued.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, rmcp owns stdio framing, a signal drops the service future, whose drop
// guard ends the session while its detached tool calls run on, and the bracket wait only observes
// the count.
pub async fn run_stdio(config_path: Option<PathBuf>) -> Result<Outcome, ServerError> {
    let (_path, config, _tracing_guard) = load_config(config_path)?;
    if !config.mcp.stdio_enabled {
        tracing::error!("stdio transport is disabled by mcp.stdio_enabled");
        return Ok(Outcome::Forbidden);
    }
    let state = StateStore::open(&config.state.resolved_dir()?)?;
    let services = Services::open(&config, state, ServicesMode::Stdio).await?;
    let handler = services.handler(&config, true)?;
    let served = crate::server_shutdown::serve_until_signal(Box::pin(serve_stdio(handler))).await;
    crate::server_shutdown::wait_for_brackets(services.workflow.brackets()).await;
    if let Err(failure) = served {
        crate::server_shutdown::flush_audit(&services.audit).await;
        services.registry.shutdown().await;
        return Err(failure);
    }
    let drain = services.jobs.drain(Duration::from_secs(30)).await;
    tracing::info!(
        cancelled = drain.cancelled,
        still_running = drain.still_running,
        "stdio jobs drained; any armed router fail-safe remains armed for rollback"
    );
    crate::server_shutdown::flush_audit(&services.audit).await;
    services.registry.shutdown().await;
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
    let path = config_path
        .or_else(|| default_config_dir().map(|directory| directory.join("kcc.toml")))
        .ok_or(ServerError::NoConfigPath)?;
    let mut config = Config::load(&path)?;
    let overrides = config.apply_env_overrides()?;
    let tracing_guard = init_tracing_from_config_strict(&config.observability)?;
    crate::privileges::log_startup_posture();
    for entry in overrides {
        tracing::info!(env_var = %entry.env_var, target = %entry.target_field, "environment override applied");
    }
    config.validate()?;
    Ok((path, config, tracing_guard))
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

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::error::Error;

    /// F-18: a failed `kcc serve` startup is a typed error that keeps its cause as
    /// `source()`.
    #[tokio::test]
    async fn a_startup_failure_keeps_its_cause() -> Result<(), Box<dyn Error>> {
        let dir = tempfile::TempDir::new()?;

        let failure = super::run_serve(Some(dir.path().join("absent.toml")))
            .await
            .err()
            .ok_or("a missing configuration must stop the server")?;

        assert!(failure.source().is_some(), "{failure:?}");
        Ok(())
    }
}
