//! The supervisor task: starts the first generations, then runs the queued changes one at
//! a time until a termination or a listener that returned on its own.

extern crate alloc;

use alloc::sync::Arc;
use core::{future::poll_fn, net::SocketAddr, pin::Pin, time::Duration};

use kcc_app::{
    mcp_settings::{Effective, ListenerKind},
    settings::McpConfig,
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::spawn_blocking,
};

use super::{
    Command, Status,
    build::{BuildError, Built, Keys, Shared, build},
    client_ca,
    generation::{Listeners, ShutdownWait, StartError},
    restart,
};
use crate::{server_error::ServerError, server_live::McpApply, server_metrics::Metrics};

/// How long a new generation may take to pass its health check, and a previous one to
/// bind its address again after a failed restart.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Windows {
    /// The health check window.
    pub(crate) health: Duration,
    /// The rebind window.
    pub(crate) rebind: Duration,
}

impl Default for Windows {
    fn default() -> Self {
        Self {
            health: Duration::from_secs(10),
            rebind: Duration::from_secs(10),
        }
    }
}

/// A point of a restart where the test hook may hold it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    /// The previous generations stopped; the new ones are not bound yet.
    Stopped,
    /// A new generation serves; its reload handle is not registered yet.
    Serving,
    /// A previous generation could not bind its address again; another attempt follows.
    Rebind,
}

/// The test hook: called at every [`Stage`]; the restart waits for its future.
pub(crate) type Pause =
    Arc<dyn Fn(Stage) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Holds a restart at a [`Stage`]; only tests set a pause.
#[derive(Clone, Default)]
pub(crate) struct Hook {
    /// The test's pause.
    pub(crate) pause: Option<Pause>,
}

impl Hook {
    /// Waits for the test's pause at `stage`, if any.
    // cancel-safe: holds nothing.
    pub(crate) async fn at(&self, stage: Stage) {
        if let Some(pause) = &self.pause {
            pause(stage).await;
        }
    }
}

/// Owns the generations; [`Supervisor::serve`] runs as its own task.
pub(crate) struct Supervisor {
    /// What every generation is built from.
    pub(super) shared: Arc<Shared>,
    /// The running generations.
    pub(super) listeners: Listeners,
    /// Applies live settings.
    pub(super) apply: Arc<McpApply>,
    /// The live settings applied now.
    pub(super) applied: Effective,
    /// The health and rebind windows.
    pub(super) windows: Windows,
    /// The test hook.
    pub(super) hook: Hook,
    /// Set when a previous generation could not serve again: the supervisor stops.
    pub(super) fatal: Option<ServerError>,
}

impl Supervisor {
    /// A supervisor of no generation yet, with `applied` as the live settings, reporting
    /// to `status`.
    pub(crate) fn new(
        shared: Arc<Shared>,
        applied: Effective,
        status: watch::Sender<Status>,
    ) -> Self {
        let apply = Arc::new(McpApply::new(
            Arc::clone(&shared.live),
            Arc::clone(&shared.reload),
        ));
        let oauth = shared
            .sign_in
            .as_ref()
            .map(|sign_in| Arc::clone(sign_in.server()));
        Self {
            shared,
            listeners: Listeners::new(status, oauth),
            apply,
            applied,
            windows: Windows::default(),
            hook: Hook::default(),
            fatal: None,
        }
    }

    /// Uses `windows` and `hook` (tests).
    #[cfg(test)]
    pub(crate) fn with(mut self, windows: Windows, hook: Hook) -> Self {
        self.windows = windows;
        self.hook = hook;
        self
    }

    /// Starts the main generation and, when enabled, the dedicated one; `ready` gets the
    /// main listener's address once it serves.
    ///
    /// A main generation that cannot be built from the effective settings starts with
    /// kcc.toml's sign-in settings (`[mcp.auth.*]`, `[mcp.dedicated]`) instead; a
    /// dedicated generation that cannot be built or bound is skipped. Both are logged and
    /// reported in the status.
    ///
    /// # Errors
    ///
    /// The main generation could not be built even so, or not bound.
    // NOT cancel-safe: dropped after a start, that generation is cancelled but not awaited.
    pub(crate) async fn start(
        mut self,
        ready: oneshot::Sender<SocketAddr>,
    ) -> Result<Self, ServerError> {
        let effective = self.applied.settings().clone();
        let (built, settings, fallback) = match blocking_build(
            &self.shared,
            ListenerKind::Main,
            &effective,
            Keys::Required,
        )
        .await
        {
            Ok(built) => (built, effective, None),
            Err(error) => {
                let mut toml = effective.clone();
                toml.auth.clone_from(&self.shared.config.mcp.auth);
                toml.dedicated.clone_from(&self.shared.config.mcp.dedicated);
                if toml == effective {
                    return Err(error.into());
                }
                tracing::warn!(%error, "the main listener cannot use the MCP sign-in settings saved on the Web; starting with kcc.toml's");
                let built =
                    blocking_build(&self.shared, ListenerKind::Main, &toml, Keys::Required).await?;
                (built, toml, Some(error.to_string()))
            }
        };
        let server = &self.shared.config.server;
        let address = self
            .listeners
            .start(built, None)
            .await
            .map_err(|error| match error {
                StartError::Bind(source) => ServerError::Bind {
                    address: server.listen_addr.clone(),
                    port: server.listen_port,
                    source,
                },
                StartError::Serve(reason) => ServerError::Start {
                    listener: "main",
                    reason,
                },
            })?;
        self.register_at_start(ListenerKind::Main).await;
        if ready.send(address).is_err() {
            tracing::debug!("the state watcher was gone before the main listener served");
        }
        let skipped = self.start_dedicated(&settings).await;
        self.listeners.note(fallback, skipped);
        Ok(self)
    }

    /// Starts the dedicated generation when `settings` enable it; the reason it was
    /// skipped otherwise.
    // NOT cancel-safe: as `Listeners::start`.
    async fn start_dedicated(&mut self, settings: &McpConfig) -> Option<String> {
        if !settings.dedicated.enabled {
            return None;
        }
        let reason = match blocking_build(
            &self.shared,
            ListenerKind::Dedicated,
            settings,
            Keys::Required,
        )
        .await
        {
            Err(error) => error.to_string(),
            Ok(built) => match self.listeners.start(built, None).await {
                Ok(_address) => {
                    self.register_at_start(ListenerKind::Dedicated).await;
                    return None;
                }
                Err(StartError::Bind(error)) => error.to_string(),
                Err(StartError::Serve(reason)) => reason,
            },
        };
        tracing::warn!(%reason, "dedicated MCP listener skipped; the main listener serves");
        Some(reason)
    }

    /// Registers the `kind` generation at start; a failure is logged.
    // cancel-safe: as `Listeners::register`.
    async fn register_at_start(&mut self, kind: ListenerKind) {
        if let Err(error) = self
            .listeners
            .register(kind, &self.shared.reload, self.windows.health)
            .await
        {
            tracing::error!(%error, "the MCP server keeps its start-up keys and roles until the next reload");
        }
    }

    /// Runs the queued changes one at a time until `termination` resolves, a listener
    /// returns on its own, or a failed restart cannot serve the previous generation again;
    /// then stops every generation, waits until each drained, and returns.
    ///
    /// A termination wins over a change in progress (dropped where it stands; its new
    /// generations are stopped as well) and over the changes still queued (never run).
    ///
    /// # Errors
    ///
    /// The error of a listener that returned with one, or the failed rebind.
    // NOT cancel-safe: dropped, the generations are cancelled but not awaited.
    pub(crate) async fn serve<T>(
        mut self,
        mut queue: mpsc::UnboundedReceiver<Command>,
        termination: T,
    ) -> Result<(), ServerError>
    where
        T: Future<Output = ()>,
    {
        tokio::pin!(termination);
        let mut open = true;
        let outcome = loop {
            let command = tokio::select! {
                biased;
                () = &mut termination => break Ok(()),
                ended = poll_fn(|cx| self.listeners.poll_ended(cx)) => break ended,
                command = queue.recv(), if open => command,
            };
            let Some(next) = command else {
                open = false;
                continue;
            };
            let finished = tokio::select! {
                biased;
                () = &mut termination => false,
                () = self.run(next) => true,
            };
            if !finished {
                break Ok(());
            }
            if let Some(fatal) = self.fatal.take() {
                break Err(fatal);
            }
        };
        self.listeners.stop_every(&self.shared.reload).await;
        tracing::info!("listeners stopped");
        outcome
    }

    /// Runs one change and sends its result.
    // NOT cancel-safe: as `restart::restart`.
    async fn run(&mut self, command: Command) {
        match command {
            Command::Restart(candidate, reply) => {
                let result = Box::pin(restart::restart(self, &candidate)).await;
                drop(reply.send(result));
            }
            Command::ApplyLive(candidate, reply) => {
                let result = Box::pin(restart::apply_live(self, &candidate)).await;
                drop(reply.send(result));
            }
            Command::ReplaceCa(anchor, pem, confirmed, reply) => {
                let result = Box::pin(client_ca::replace(self, anchor, pem, confirmed)).await;
                drop(reply.send(result));
            }
        }
    }

    /// What a stopped generation waits for.
    pub(super) fn shutdown_wait(&self) -> ShutdownWait {
        ShutdownWait {
            metrics: self.shared.metrics.as_ref().map(Metrics::bind),
            window: self.windows.rebind,
        }
    }
}

/// Builds the `kind` generation off the async executor.
///
/// # Errors
///
/// As [`build`].
// cancel-safe: the build runs to completion on its own thread; dropping only discards it.
pub(super) async fn blocking_build(
    shared: &Arc<Shared>,
    kind: ListenerKind,
    settings: &McpConfig,
    keys: Keys,
) -> Result<Built, BuildError> {
    let (parts, wanted) = (Arc::clone(shared), settings.clone());
    spawn_blocking(move || build(&parts, kind, &wanted, keys))
        .await
        .map_err(|error| BuildError::Task(error.to_string()))?
}
