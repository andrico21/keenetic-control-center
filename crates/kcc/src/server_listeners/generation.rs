//! Running listener generations: start, registration with the reload fan-out, stop.

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use std::{io, net::TcpListener as StdListener};

use kcc_app::{mcp_settings::ListenerKind, settings::McpConfig};
use kcc_web::admin::{ReloadError, TransportReload};
use rmcp_server_kit::{
    RmcpServerKitError,
    transport::{ReloadHandle, serve_with_listener},
};
use tokio::{
    net::TcpListener,
    sync::{oneshot, watch},
    task::{JoinHandle, spawn_blocking},
    time::{Instant, interval},
};
use tokio_util::sync::CancellationToken;

use super::{Listening, Status, build::Built, health::Probe, name};
use crate::server_error::ServerError;

/// The pause between two binds of an address still in use.
pub(super) const RETRY: Duration = Duration::from_millis(100);

/// One kit server.
struct Generation {
    /// Counts the generations of the process, from 1.
    number: u64,
    /// The address it bound.
    address: SocketAddr,
    /// The settings it was built from.
    settings: McpConfig,
    /// Its health check.
    probe: Probe,
    /// Stops it; cancelled on drop as well.
    token: CancellationToken,
    /// The kit server; `None` once it returned.
    task: Option<JoinHandle<Result<(), RmcpServerKitError>>>,
    /// Its reload handle, until registered.
    handles: Option<oneshot::Receiver<ReloadHandle>>,
}

impl Drop for Generation {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

/// A stopped generation's address and settings, to serve it again.
pub(super) struct Previous {
    /// The listener.
    pub(super) kind: ListenerKind,
    /// The address it had bound.
    pub(super) address: SocketAddr,
    /// The settings it was built from.
    pub(super) settings: McpConfig,
}

/// What a stopped generation waits for before the next one binds.
#[derive(Debug, Clone, Copy)]
pub(super) struct ShutdownWait {
    /// The metrics address, when the main listener serves metrics.
    pub(super) metrics: Option<SocketAddr>,
    /// How long to wait for each address.
    pub(super) window: Duration,
}

/// Why a generation did not start.
pub(super) enum StartError {
    /// Its address could not be bound.
    Bind(io::Error),
    /// The kit server stopped before it served.
    Serve(String),
}

/// The running generations, by listener.
pub(super) struct Listeners {
    /// Each listener's current generation.
    running: BTreeMap<ListenerKind, Generation>,
    /// The last generation number handed out.
    counter: u64,
    /// Reports the running generations.
    status: watch::Sender<Status>,
}

impl Listeners {
    /// No generation yet; `status` receives every change.
    pub(super) const fn new(status: watch::Sender<Status>) -> Self {
        Self {
            running: BTreeMap::new(),
            counter: 0,
            status,
        }
    }

    /// Binds `built` (at `at` instead of its configured address when set), serves it, and
    /// waits until it listens.
    // NOT cancel-safe: dropped after the bind, the started generation is not recorded; its
    // token is cancelled, so the kit server stops on its own.
    pub(super) async fn start(
        &mut self,
        built: Built,
        at: Option<SocketAddr>,
    ) -> Result<SocketAddr, StartError> {
        let listener = TcpListener::bind(at.unwrap_or(built.bind))
            .await
            .map_err(StartError::Bind)?;
        let (ready, listening) = oneshot::channel();
        let token = CancellationToken::new();
        let factory = built.factory;
        self.counter = self.counter.saturating_add(1);
        let mut generation = Generation {
            number: self.counter,
            address: built.bind,
            settings: built.settings,
            probe: built.probe,
            token: token.clone(),
            task: Some(tokio::spawn(serve_with_listener(
                listener,
                built.config,
                move || factory.handler(),
                Some(ready),
                Some(token),
            ))),
            handles: Some(built.handles),
        };
        let Ok(address) = listening.await else {
            return Err(StartError::Serve(
                generation.join().await.err().unwrap_or_default(),
            ));
        };
        generation.address = address;
        drop(self.running.insert(built.kind, generation));
        self.report();
        Ok(address)
    }

    /// Installs the current keys and roles into the `kind` generation and registers it
    /// with `reload`, waiting at most `window` for its handle.
    ///
    /// # Errors
    ///
    /// The kit handed out no handle in time, or the keys or roles could not be installed.
    // cancel-safe: dropped while waiting, the handle is kept for the next call.
    pub(super) async fn register(
        &mut self,
        kind: ListenerKind,
        reload: &Arc<TransportReload>,
        window: Duration,
    ) -> Result<(), String> {
        let generation = self
            .running
            .get_mut(&kind)
            .ok_or_else(|| "the listener is not running".to_owned())?;
        let receiver = generation
            .handles
            .as_mut()
            .ok_or_else(|| "the listener is registered already".to_owned())?;
        let handle = tokio::time::timeout(window, receiver)
            .await
            .map_err(|_elapsed| "no reload handle in time".to_owned())?
            .map_err(|_stopped| {
                "the listener stopped before it handed out its reload handle".to_owned()
            })?;
        generation.handles = None;
        let fan_out = Arc::clone(reload);
        spawn_blocking(move || fan_out.register(kind, handle))
            .await
            .map_err(|error| error.to_string())?
            .map_err(|error: ReloadError| error.to_string())
    }

    /// The `kind` generation's address and health check.
    pub(super) fn probe(&self, kind: ListenerKind) -> Option<(SocketAddr, Probe)> {
        self.running
            .get(&kind)
            .map(|generation| (generation.address, generation.probe.clone()))
    }

    /// Stops the `kind` generation, waits until its kit server returned (the kit drains
    /// for `server.shutdown_timeout`), and unregisters it from `reload`; then waits at
    /// most `wait.window` each until its address and, for a main generation, the metrics
    /// address are free again (the kit closes a TLS listener's socket on its own task).
    // NOT cancel-safe: dropped while draining, the generation stays recorded (cancelled)
    // for the next stop.
    pub(super) async fn stop(
        &mut self,
        kind: ListenerKind,
        reload: &TransportReload,
        wait: ShutdownWait,
    ) -> Option<Previous> {
        let generation = self.running.get_mut(&kind)?;
        generation.token.cancel();
        if let Err(error) = generation.join().await {
            tracing::warn!(listener = name(kind), %error, "listener stopped with an error");
        }
        reload.unregister(kind);
        let stopped = self.running.remove(&kind)?;
        self.report();
        wait_free(stopped.address, wait.window).await;
        if let (ListenerKind::Main, Some(metrics)) = (kind, wait.metrics) {
            wait_free(metrics, wait.window).await;
        }
        Some(Previous {
            kind,
            address: stopped.address,
            settings: stopped.settings.clone(),
        })
    }

    /// Stops every generation at once (they drain concurrently), then waits for each and
    /// unregisters it from `reload`.
    // NOT cancel-safe: dropped while draining, the remaining generations are cancelled but
    // not awaited.
    pub(super) async fn stop_every(&mut self, reload: &TransportReload) {
        for generation in self.running.values() {
            generation.token.cancel();
        }
        for (kind, generation) in &mut self.running {
            if let Err(error) = generation.join().await {
                tracing::warn!(listener = name(*kind), %error, "listener stopped with an error");
            }
            reload.unregister(*kind);
        }
        self.running.clear();
        self.report();
    }

    /// Resolves when any generation's kit server returned; the kit returns on its own on
    /// SIGTERM or Ctrl-C, or with an error.
    pub(super) fn poll_ended(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ServerError>> {
        for (kind, generation) in &mut self.running {
            let Some(task) = generation.task.as_mut() else {
                continue;
            };
            if let Poll::Ready(ended) = Pin::new(task).poll(cx) {
                generation.task = None;
                tracing::info!(listener = name(*kind), "listener returned");
                return Poll::Ready(match ended {
                    Ok(served) => served.map_err(ServerError::from),
                    Err(_aborted) => Err(ServerError::ListenerTask),
                });
            }
        }
        Poll::Pending
    }

    /// Records `fallback` and `skipped` in the status.
    pub(super) fn note(&self, fallback: Option<String>, skipped: Option<String>) {
        self.status.send_modify(|status| {
            status.fallback = fallback;
            status.skipped = skipped;
        });
    }

    /// Forgets the start-up notes of the listeners in `kinds` once they restarted.
    pub(super) fn clear_notes(&self, kinds: &[ListenerKind]) {
        self.status.send_modify(|status| {
            if kinds.contains(&ListenerKind::Main) {
                status.fallback = None;
            }
            if kinds.contains(&ListenerKind::Dedicated) {
                status.skipped = None;
            }
        });
    }

    /// Publishes the running generations.
    fn report(&self) {
        let listening = |kind| {
            self.running.get(&kind).map(|generation| Listening {
                address: generation.address,
                generation: generation.number,
            })
        };
        let (main, dedicated) = (
            listening(ListenerKind::Main),
            listening(ListenerKind::Dedicated),
        );
        self.status.send_modify(|status| {
            status.main = main;
            status.dedicated = dedicated;
        });
    }
}

impl Generation {
    /// Waits until the kit server returned; `Ok` when it was already awaited.
    // cancel-safe: the task stays in place until it completed.
    async fn join(&mut self) -> Result<(), String> {
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        let ended = task.await;
        self.task = None;
        match ended {
            Ok(served) => served.map_err(|error| error.to_string()),
            Err(aborted) => Err(aborted.to_string()),
        }
    }
}

/// Waits at most `window` until `address` can be bound again (a stopped generation's
/// TLS and metrics listeners close their sockets on their own tasks).
// cancel-safe: holds no socket across an await.
async fn wait_free(address: SocketAddr, window: Duration) {
    let deadline = Instant::now().checked_add(window);
    let mut ticks = interval(RETRY);
    loop {
        match StdListener::bind(address) {
            Ok(free) => return drop(free),
            Err(error) if deadline.is_some_and(|end| Instant::now() < end) => {
                tracing::debug!(%address, %error, "stopped listener's address still in use");
            }
            Err(error) => {
                tracing::warn!(%address, %error, "stopped listener's address still in use; starting anyway");
                return;
            }
        }
        let _: Instant = ticks.tick().await;
    }
}
