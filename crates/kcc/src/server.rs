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

use arc_swap::ArcSwap;
use kcc_app::{
    audit::AuditLog,
    mcp_settings::{EnvOverrides, McpBase},
    persist::StateStore,
    settings::{Config, default_config_dir},
};
use kcc_web::admin::TransportReload;
use rmcp_server_kit::{
    observability::init_tracing_from_config_strict,
    transport::{ReadinessCheck, serve_stdio},
};
use serde_json::json;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::{
    server_error::{Outcome, ServerError},
    server_listeners::{
        ListenerSupervisor, build::Shared, control::WebHandle, supervisor::Supervisor,
    },
    server_mcp_auth::{KccSignIn, authorization_server},
    server_notify::{self, Deps, NotifyHandle, Options},
    server_reload::{hangups, start_watch},
    server_schedules::{self, wiring::start_for_server},
    server_services::{Services, ServicesMode},
    server_shutdown::{BRACKET_GRACE, Termination},
    server_web::web_state,
    state_watch::StateWatch,
};

/// Runs the HTTP server command.
// NOT cancel-safe: once the listeners start, shutdown must be driven cooperatively by the
// supervisor.
pub async fn run_serve(config_path: Option<PathBuf>) -> Result<Outcome, ServerError> {
    let hangups = hangups();
    let termination = Termination::install();
    let (path, config, mcp_base, _tracing_guard) = load_config(config_path)?;
    crate::server_tls_key::check(&config)?;
    let state_dir = config.state.resolved_dir()?;
    let state = StateStore::open(&state_dir)?;
    let _state_lock = state
        .try_lock("server")
        .map_err(|source| ServerError::ServerLock {
            dir: state_dir.clone(),
            source,
        })?;
    let effective = mcp_base.effective(&state)?;
    let mcp = effective.settings();
    let mut services = Services::open(&config, state, ServicesMode::Serve).await?;
    let notify = NotifyHandle::start(
        Deps::from_services(&services),
        Options::from_config(&config)?,
    )
    .await?;
    let (scheduler, schedule_control) = start_for_server(&services, &notify, &config);
    let handler = services.handler(&config, mcp, mcp.http_enabled)?;
    let tools = handler.tool_specs().to_vec();
    let live = Arc::new(ArcSwap::from_pointee(handler));
    let auth_reload = Arc::new(
        TransportReload::new(services.state.clone(), tools)
            .with_role_source(services.roles.clone()),
    );
    let updates = crate::server_tasks::refresh_updates(Arc::clone(&services.updates));
    let oauth = authorization_server(&config, &services);
    let (supervisor, queue, status) = ListenerSupervisor::channel();
    let web_state = if config.web.enabled {
        Some(
            web_state(
                &services,
                (&config, mcp_base),
                Arc::clone(&auth_reload),
                (Arc::new(notify.clone()), schedule_control),
            )?
            .with_mcp_control(Arc::new(WebHandle::new(supervisor.clone())))
            .with_oauth(oauth.clone()),
        )
    } else {
        None
    };
    let _sessions = web_state.as_ref().and_then(|web| {
        let metrics = services.metrics.clone()?;
        Some(crate::server_tasks::track_sessions(web.clone(), metrics))
    });
    let (listen_ready, listening) = oneshot::channel();
    start_watch(
        StateWatch::new(Arc::clone(&auth_reload), web_state.clone())
            .with_follower(server_notify::FILES, notify.follower())
            .with_follower(server_schedules::FILES, scheduler.follower()),
        (hangups, listening),
        (path, Arc::clone(&services.registry)),
    );
    let shared = Shared {
        metrics: crate::server_metrics::start(&services, &config)?,
        readiness: readiness_check(services.state.dir().to_owned(), services.audit.clone()),
        state: services.state.clone(),
        web: web_state,
        live,
        reload: auth_reload,
        sign_in: oauth.map(|server| Arc::new(KccSignIn::new(server))),
        config,
    };
    let _supervisor = supervisor;
    let started =
        Box::pin(Supervisor::new(Arc::new(shared), effective, status).start(listen_ready)).await?;
    let stop = CancellationToken::new();
    let stopping = stop.clone();
    let supervising = tokio::spawn(started.serve(queue, async move {
        tokio::select! {
            () = termination.wait() => {}
            () = stopping.cancelled() => {}
        }
    }));
    let serve_result = crate::server_shutdown::serve_until_shutdown(
        async move { supervising.await.unwrap_or(Err(ServerError::ListenerTask)) },
        &services.audit,
        || {
            stop.cancel();
            scheduler.stop_token().cancel();
        },
    )
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
    let (_path, config, mcp_base, _tracing_guard) = load_config(config_path)?;
    let state = StateStore::open(&config.state.resolved_dir()?)?;
    let mcp = mcp_base.effective(&state)?.into_settings();
    if !mcp.stdio_enabled {
        tracing::error!("stdio transport is disabled by mcp.stdio_enabled");
        return Ok(Outcome::Forbidden);
    }
    let services = Services::open(&config, state, ServicesMode::Stdio).await?;
    let handler = services.handler(&config, &mcp, true)?;
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

/// Loads, overrides, traces, and validates one configuration generation, and captures its
/// `[mcp]` with the keys the environment set, for [`McpBase::effective`].
fn load_config(
    config_path: Option<PathBuf>,
) -> Result<
    (
        PathBuf,
        Config,
        McpBase,
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
    for entry in &overrides {
        tracing::info!(env_var = %entry.env_var, target = %entry.target_field, "environment override applied");
    }
    config.validate()?;
    let mcp = McpBase::new(&config, &EnvOverrides::from_reports(&overrides));
    Ok((path, config, mcp, tracing_guard))
}

/// Builds the state-directory and audit-writer readiness probe.
pub(crate) fn readiness_check(state_dir: PathBuf, audit: AuditLog) -> ReadinessCheck {
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
