//! Reloads of a running `kcc serve`: the state watcher and SIGHUP.
#![expect(
    clippy::missing_errors_doc,
    reason = "binary assembly: the reload errors are logged, not returned to an API caller"
)]

extern crate alloc;

use alloc::sync::Arc;
use std::path::PathBuf;
#[cfg(unix)]
use std::{io, path::Path};

use kcc_app::registry::RouterRegistry;
#[cfg(unix)]
use kcc_app::{permissions::load_roles, settings::Config};
#[cfg(unix)]
use kcc_web::admin::TransportReload;
use rmcp_server_kit::transport::McpServerConfig;
#[cfg(unix)]
use tokio::signal::unix::{Signal, SignalKind, signal};

#[cfg(unix)]
use crate::server_error::ServerError;
use crate::state_watch::StateWatch;

/// The SIGHUP stream of `kcc serve`, installed before anything else starts so that a
/// SIGHUP during startup is kept for the watcher instead of ending the process.
#[cfg(unix)]
pub(crate) type Hangups = io::Result<Signal>;

/// No SIGHUP on non-Unix platforms.
#[cfg(not(unix))]
pub(crate) struct Hangups;

/// Installs the SIGHUP stream.
#[cfg(unix)]
pub(crate) fn hangups() -> Hangups {
    signal(SignalKind::hangup())
}

/// No SIGHUP on non-Unix platforms.
#[cfg(not(unix))]
pub(crate) const fn hangups() -> Hangups {
    Hangups
}

/// Hands the transport's reload handle to the Web UI and starts `watch` with SIGHUP.
///
/// The handle goes to the slot of `watch`'s transport, for the administration pages;
/// `watch` applies key and account changes made outside the server. A SIGHUP applies
/// the API keys and accounts as the watcher does, then reloads the roles (MCP RBAC, the
/// MCP handlers and the Web UI) and the router profiles from `path`.
#[cfg(unix)]
pub(crate) fn with_reload(
    config: McpServerConfig,
    watch: StateWatch,
    hangups: Hangups,
    (path, registry): (PathBuf, Arc<RouterRegistry>),
) -> McpServerConfig {
    let slot = watch.transport().slot();
    let auth = Arc::clone(watch.transport());
    config.with_reload_callback(move |handle| {
        if slot.set(handle).is_err() {
            tracing::error!("the MCP transport delivered a second reload handle; keeping the first");
        }
        drop(tokio::spawn(watch.run(hangups, move || {
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
pub(crate) fn with_reload(
    config: McpServerConfig,
    watch: StateWatch,
    _hangups: Hangups,
    _reload: (PathBuf, Arc<RouterRegistry>),
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
    let mut config = Config::load(path)?;
    drop(config.apply_env_overrides()?);
    config.validate()?;
    let roles = load_roles(auth.state())?;
    let invalidated = registry.reload(&config).await?;
    auth.install_roles(roles)?;
    tracing::info!(invalidated, "configuration reloaded from SIGHUP");
    Ok(())
}
