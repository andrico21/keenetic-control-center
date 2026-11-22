//! Reloads of a running `kcc serve`: the state watcher and SIGHUP.
#![expect(
    clippy::missing_errors_doc,
    reason = "binary assembly: the reload errors are logged, not returned to an API caller"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::net::SocketAddr;
use std::path::PathBuf;
#[cfg(unix)]
use std::{io, path::Path};

use kcc_app::registry::RouterRegistry;
#[cfg(unix)]
use kcc_app::{permissions::load_roles, settings::Config};
#[cfg(unix)]
use kcc_web::admin::TransportReload;
#[cfg(unix)]
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::oneshot;

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

/// Resolves with the listening address once the first MCP server serves.
pub(crate) type Serving = oneshot::Receiver<SocketAddr>;

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

/// Starts `watch` with SIGHUP once per `kcc serve`, when its first MCP server listens
/// (`serving` resolves); never when that server does not start.
///
/// `watch` applies key and account changes made outside the server to every MCP server
/// registered with its transport (the listener supervisor registers each generation). A SIGHUP applies the API keys and
/// accounts as the watcher does, then reloads the roles (MCP RBAC, the MCP handlers and
/// the Web UI) and the router profiles from `path`.
#[cfg(unix)]
pub(crate) fn start_watch(
    watch: StateWatch,
    (hangups, serving): (Hangups, Serving),
    (path, registry): (PathBuf, Arc<RouterRegistry>),
) {
    let auth = Arc::clone(watch.transport());
    let run = watch.run(hangups, move || {
        let (transport, file, routers) = (Arc::clone(&auth), path.clone(), Arc::clone(&registry));
        async move {
            if let Err(error) = reload(&transport, &file, &routers).await {
                tracing::error!(%error, "SIGHUP reload rejected; previous configuration remains active");
            }
        }
    });
    drop(tokio::spawn(async move {
        if serving.await.is_ok() {
            run.await;
        }
    }));
}

/// Starts `watch` once per `kcc serve`, when its first MCP server listens (`serving`
/// resolves); never when that server does not start.
///
/// SIGHUP reload is unavailable on non-Unix platforms.
#[cfg(not(unix))]
pub(crate) fn start_watch(
    watch: StateWatch,
    (_hangups, serving): (Hangups, Serving),
    _reload: (PathBuf, Arc<RouterRegistry>),
) {
    drop(tokio::spawn(async move {
        if serving.await.is_ok() {
            watch.run().await;
        }
    }));
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
    auth.install_roles(roles);
    tracing::info!(invalidated, "configuration reloaded from SIGHUP");
    Ok(())
}
