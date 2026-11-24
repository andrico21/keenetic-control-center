//! The listeners of `kcc serve`: the main listener (Web UI, MCP, health, metrics) and the
//! optional MCP-only dedicated listener, each run as a sequence of generations.
//!
//! A [`ListenerSupervisor`] queues settings changes for the supervisor task that owns the
//! generations, so every change runs in one serialized section outside the request that
//! asked for it. A change that names listeners to restart builds and validates their new
//! generations first, stops the old ones, serves the new ones, registers each with the
//! key and role reload fan-out, and health-checks them; any failure stops them again and
//! serves the previous generations on their previous addresses. Only after every check
//! passed are the live settings applied and `mcp_settings.json` written. A termination
//! signal stops every generation at any moment, a pending change included.
#![expect(
    clippy::absolute_paths,
    clippy::field_scoped_visibility_modifiers,
    clippy::missing_errors_doc,
    reason = "binary assembly: the supervisor's parts share their fields within this module, and its errors are typed enums documented on the public API"
)]

pub mod build;
mod client_ca;
pub(crate) mod control;
mod generation;
mod health;
mod restart;
mod revert;
pub mod sign_in;
pub(crate) mod supervisor;
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions are not rendered API documentation"
)]
mod tests;
mod tls;

use core::{fmt, net::SocketAddr};

use kcc_app::mcp_settings::{Candidate, ListenerKind, SettingsError, client_ca::CaError};
use kcc_web::admin::ReloadError;
use tokio::sync::{mpsc, oneshot, watch};

use self::{build::BuildError, client_ca::Anchor};

/// Queues MCP settings changes for the running listeners of `kcc serve`; cheap to clone.
#[derive(Clone)]
pub struct ListenerSupervisor {
    /// The supervisor task's queue.
    commands: mpsc::UnboundedSender<Command>,
    /// The listeners as the supervisor last reported them.
    status: watch::Receiver<Status>,
}

/// One queued change and where its result goes.
pub(crate) enum Command {
    /// Restarts the candidate's listeners, then applies and saves it.
    Restart(Candidate, oneshot::Sender<Result<Restarted, ListenerError>>),
    /// Applies and saves a candidate that restarts no listener.
    ApplyLive(Candidate, oneshot::Sender<Result<(), ListenerError>>),
    /// Replaces a trust anchor (`confirmed`: the password was re-entered) and restarts the
    /// listeners using it.
    ReplaceCa(
        Anchor,
        Vec<u8>,
        bool,
        oneshot::Sender<Result<Restarted, ListenerError>>,
    ),
}

/// The result of [`ListenerSupervisor::restart`].
#[derive(Debug)]
#[non_exhaustive]
pub enum Restarted {
    /// The new generations serve, the settings are applied and saved.
    Applied,
    /// A step failed; the previous generations serve again on their previous addresses
    /// and neither the live settings nor `mcp_settings.json` changed.
    Reverted(RevertReason),
}

/// Why a restart was reverted.
#[derive(Debug)]
#[non_exhaustive]
pub enum RevertReason {
    /// The new generation could not bind its address.
    Bind {
        /// The listener.
        listener: ListenerKind,
        /// The bind failure.
        reason: String,
    },
    /// The new generation stopped before it served.
    Serve {
        /// The listener.
        listener: ListenerKind,
        /// The kit's failure.
        reason: String,
    },
    /// The current keys and roles could not be installed into the new generation.
    Register {
        /// The listener.
        listener: ListenerKind,
        /// The reload failure.
        reason: String,
    },
    /// The new generation did not pass its health check within 10 seconds.
    Health {
        /// The listener.
        listener: ListenerKind,
        /// What failed.
        reason: String,
    },
    /// The live settings could not be applied.
    Apply(ReloadError),
    /// `mcp_settings.json` could not be written.
    Commit(SettingsError),
    /// A step ended abnormally.
    Task(String),
}

/// Why a change was refused before any listener stopped, or did not finish.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ListenerError {
    /// `mcp_settings.json` changed since the candidate was planned; nothing changed.
    #[error("the MCP settings changed since this change was planned")]
    SettingsChanged,
    /// `mcp_settings.json` could not be read; nothing changed.
    #[error("{0}")]
    Settings(SettingsError),
    /// A new generation could not be built from the candidate; nothing changed.
    #[error("the {listener} listener cannot use these settings: {source}")]
    Build {
        /// The listener.
        listener: &'static str,
        /// Why.
        #[source]
        source: BuildError,
    },
    /// [`ListenerSupervisor::apply_live`] got a candidate that restarts a listener.
    #[error("this change restarts a listener")]
    RestartRequired,
    /// The live settings could not be applied; the previous ones were applied again and
    /// nothing was saved.
    #[error("{0}")]
    Apply(ReloadError),
    /// `mcp_settings.json` could not be written; the previous settings were applied again.
    #[error("{0}")]
    Commit(SettingsError),
    /// A step ended abnormally; the previous settings were applied again.
    #[error("the change ended abnormally: {0}")]
    Task(String),
    /// `kcc serve` is stopping; the change did not run or did not finish.
    #[error("kcc serve is stopping")]
    ShuttingDown,
    /// A listener uses the client CA or the identity provider's CA bundle and its
    /// replacement was not confirmed with the password; nothing changed.
    #[error("replacing a CA in use needs the password")]
    ConfirmationRequired,
    /// The client CA could not be checked, stored or put back.
    #[error("client CA: {0}")]
    ClientCa(CaError),
    /// The identity provider's CA bundle could not be checked, stored or put back.
    #[error("identity provider CA bundle: {0}")]
    IdpCa(CaError),
}

/// The listeners of a running `kcc serve`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Status {
    /// The main listener.
    pub main: Option<Listening>,
    /// The dedicated MCP listener, when it serves.
    pub dedicated: Option<Listening>,
    /// Why the main listener started with kcc.toml's sign-in settings instead of the
    /// effective ones (the Web overrides of `[mcp.auth.*]` and `[mcp.dedicated]` are
    /// ignored until the next start or restart).
    pub fallback: Option<String>,
    /// Why the dedicated listener was skipped at start.
    pub skipped: Option<String>,
}

/// One serving generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Listening {
    /// The bound address.
    pub address: SocketAddr,
    /// Counts the generations of the process, from 1.
    pub generation: u64,
}

impl fmt::Debug for ListenerSupervisor {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerSupervisor")
            .field("status", &*self.status.borrow())
            .finish_non_exhaustive()
    }
}

impl ListenerSupervisor {
    /// A handle, the supervisor's queue and its status channel.
    pub(crate) fn channel() -> (
        Self,
        mpsc::UnboundedReceiver<Command>,
        watch::Sender<Status>,
    ) {
        let (commands, queue) = mpsc::unbounded_channel();
        let (report, status) = watch::channel(Status::default());
        (Self { commands, status }, queue, report)
    }

    /// Restarts every listener `candidate` names as one unit, then applies its live
    /// settings and saves it. The change is queued when this is called, so calls run in
    /// the order they were made; dropping the returned future does not stop the change.
    ///
    /// # Errors
    ///
    /// [`ListenerError`] when the change was refused before any listener stopped or
    /// `kcc serve` stopped meanwhile.
    #[inline]
    pub fn restart(
        &self,
        candidate: Candidate,
    ) -> impl Future<Output = Result<Restarted, ListenerError>> + Send + 'static {
        let (reply, result) = oneshot::channel();
        let queued = self.commands.send(Command::Restart(candidate, reply));
        // cancel-safe: only awaits the reply; the change runs in the supervisor.
        async move {
            queued.map_err(|_stopped| ListenerError::ShuttingDown)?;
            result
                .await
                .map_err(|_stopped| ListenerError::ShuttingDown)?
        }
    }

    /// Applies and saves `candidate`, which restarts no listener, in the same serialized
    /// section as [`ListenerSupervisor::restart`].
    ///
    /// # Errors
    ///
    /// As [`ListenerSupervisor::restart`]; [`ListenerError::RestartRequired`] when the
    /// candidate names a listener.
    #[inline]
    pub fn apply_live(
        &self,
        candidate: Candidate,
    ) -> impl Future<Output = Result<(), ListenerError>> + Send + 'static {
        let (reply, result) = oneshot::channel();
        let queued = self.commands.send(Command::ApplyLive(candidate, reply));
        // cancel-safe: only awaits the reply; the change runs in the supervisor.
        async move {
            queued.map_err(|_stopped| ListenerError::ShuttingDown)?;
            result
                .await
                .map_err(|_stopped| ListenerError::ShuttingDown)?
        }
    }

    /// Replaces the client CA with `pem` in the same serialized section as
    /// [`ListenerSupervisor::restart`], then restarts every listener whose
    /// client-certificate sign-in is on, as one unit; a failed restart puts the previous CA
    /// back and serves the previous listeners again. `confirmed` says the actor re-entered
    /// the password, which a replacement needs while a listener uses client certificates.
    ///
    /// # Errors
    ///
    /// [`ListenerError::ConfirmationRequired`], [`ListenerError::ClientCa`] or a build
    /// failure when nothing changed; [`ListenerError::ShuttingDown`] as for a restart.
    #[inline]
    pub fn replace_client_ca(
        &self,
        pem: Vec<u8>,
        confirmed: bool,
    ) -> impl Future<Output = Result<Restarted, ListenerError>> + Send + 'static {
        self.replace_ca(Anchor::Client, pem, confirmed)
    }

    /// Replaces the identity provider's CA bundle with `pem` as
    /// [`ListenerSupervisor::replace_client_ca`] replaces the client CA, restarting every
    /// listener whose `oauth` is `external`.
    ///
    /// # Errors
    ///
    /// As [`ListenerSupervisor::replace_client_ca`], with [`ListenerError::IdpCa`].
    #[inline]
    pub fn replace_idp_ca(
        &self,
        pem: Vec<u8>,
        confirmed: bool,
    ) -> impl Future<Output = Result<Restarted, ListenerError>> + Send + 'static {
        self.replace_ca(Anchor::IdentityProvider, pem, confirmed)
    }

    /// Queues the replacement of `anchor` with `pem`.
    fn replace_ca(
        &self,
        anchor: Anchor,
        pem: Vec<u8>,
        confirmed: bool,
    ) -> impl Future<Output = Result<Restarted, ListenerError>> + Send + 'static {
        let (reply, result) = oneshot::channel();
        let queued = self
            .commands
            .send(Command::ReplaceCa(anchor, pem, confirmed, reply));
        // cancel-safe: only awaits the reply; the change runs in the supervisor.
        async move {
            queued.map_err(|_stopped| ListenerError::ShuttingDown)?;
            result
                .await
                .map_err(|_stopped| ListenerError::ShuttingDown)?
        }
    }

    /// The listeners as the supervisor last reported them.
    #[inline]
    #[must_use]
    pub fn status(&self) -> Status {
        self.status.borrow().clone()
    }
}

/// The name of `kind` in logs and errors.
pub(crate) const fn name(kind: ListenerKind) -> &'static str {
    match kind {
        ListenerKind::Main => "main",
        ListenerKind::Dedicated | _ => "dedicated",
    }
}
