//! Fake Entware SSH server: dropbear's exec surface with `opkg` and rc.func init scripts.
//!
//! [`FakeEntwareSsh::spawn`] serves SSH on loopback with an ed25519 host key, password
//! and `authorized_keys` authentication for [`USER`], and an in-memory Entware userland:
//! an `opkg` package database and `/opt/etc/init.d/S*` services whose actions follow
//! Entware's `rc.func` (output, ANSI colours and exit codes). Only the exec strings of
//! kcc's closed Entware command set are understood, matched against fixed templates;
//! every other command answers 127 as the shell does for a missing program. The fake never
//! logs the password, a key or command output.

use alloc::{collections::BTreeMap, sync::Arc};
use core::{
    fmt,
    net::{Ipv4Addr, SocketAddr},
};
use std::{
    io,
    sync::{Mutex, MutexGuard, PoisonError},
};

use rand::RngExt as _;
use russh::keys::{PrivateKey, PublicKey, ssh_key::private};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use zeroize::Zeroizing;

mod command;
mod connection;
mod system;

/// The only login the fake accepts, as on Entware's dropbear.
pub const USER: &str = "root";

/// Entware's default root password, accepted unless [`Config::password`] replaces it.
pub const DEFAULT_PASSWORD: &str = "keenetic";

/// Lines of filler [`Fault::HugeOutput`] appends to a command's output.
const HUGE_OUTPUT_LINES: usize = 19_200;

/// One line of [`Fault::HugeOutput`] filler, 16 bytes.
const HUGE_OUTPUT_LINE: &str = "huge output 012\n";

/// One fault switch; it applies to every command until it is replaced or cleared.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Fault {
    /// Accept the command and never answer it.
    Hang,
    /// Run the command and append 300 KiB of filler to its output.
    HugeOutput,
    /// Run the command, send its output, then close the channel without an exit status.
    NoExitStatus,
    /// Drop the connection on every command once this many commands were received.
    KillAfter(u64),
}

/// Activity counters since the fake started.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Counters {
    /// Accepted TCP connections.
    pub connections: u64,
    /// Password requests and public-key offers evaluated.
    pub auth_attempts: u64,
    /// Exec requests received, faulted ones included.
    pub commands: u64,
}

/// One `/opt/etc/init.d/S*` service.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Service {
    /// rc.func's `PROC`, also used as its `DESC`.
    process: String,
    /// rc.func's `ENABLED=yes`.
    enabled: bool,
    /// Whether the process runs.
    running: bool,
    /// Whether the process ignores start and stop, so both report `failed.` and 255.
    failing: bool,
}

impl Service {
    /// An enabled, stopped service running `process`.
    #[inline]
    #[must_use]
    pub fn new<P>(process: P) -> Self
    where
        P: Into<String>,
    {
        Self {
            process: process.into(),
            enabled: true,
            running: false,
            failing: false,
        }
    }

    /// Marks the service disabled: rc.func's `start` returns 8.
    #[inline]
    #[must_use]
    pub const fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Marks the process as running.
    #[inline]
    #[must_use]
    pub const fn running(mut self) -> Self {
        self.running = true;
        self
    }

    /// Makes start and stop fail: the process state never changes and both exit 255.
    #[inline]
    #[must_use]
    pub const fn failing(mut self) -> Self {
        self.failing = true;
        self
    }

    /// Whether the process runs.
    #[inline]
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.running
    }

    /// Whether the service is enabled.
    #[inline]
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// The emulated Entware userland.
#[derive(Clone, Debug, Default)]
struct System {
    /// Installed packages: name to version.
    installed: BTreeMap<String, String>,
    /// Upgradable installed packages: name to the new version.
    upgradable: BTreeMap<String, String>,
    /// Packages the feed offers that are not installed: name to version.
    installable: BTreeMap<String, String>,
    /// Init scripts by file name (`S51dropbear`).
    services: BTreeMap<String, Service>,
    /// Contents of `/opt/etc/dropbear/authorized_keys`.
    authorized_keys: String,
}

/// What one command printed and its exit status.
#[derive(Debug, Default)]
struct Reply {
    /// Standard output.
    stdout: String,
    /// Standard error.
    stderr: String,
    /// Exit status.
    exit: u32,
}

/// Start-up state of a fake.
#[derive(Clone)]
#[non_exhaustive]
pub struct Config {
    /// Accepted password for [`USER`].
    password: Zeroizing<String>,
    /// Packages, services and `authorized_keys`.
    system: System,
    /// Listening address.
    bind: SocketAddr,
}

impl Default for Config {
    #[inline]
    fn default() -> Self {
        Self {
            password: Zeroizing::new(DEFAULT_PASSWORD.to_owned()),
            system: System::default(),
            bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        }
    }
}

impl fmt::Debug for Config {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("password", &"[REDACTED]")
            .field("system", &self.system)
            .field("bind", &self.bind)
            .finish()
    }
}

impl Config {
    /// Replaces the accepted password.
    #[inline]
    #[must_use]
    pub fn password<P>(mut self, password: P) -> Self
    where
        P: Into<String>,
    {
        self.password = Zeroizing::new(password.into());
        self
    }

    /// Replaces the `authorized_keys` text (OpenSSH lines; `ssh-ed25519 <base64> [comment]`).
    #[inline]
    #[must_use]
    pub fn authorized_keys<T>(mut self, text: T) -> Self
    where
        T: Into<String>,
    {
        self.system.authorized_keys = text.into();
        self
    }

    /// Adds an installed package.
    #[inline]
    #[must_use]
    pub fn installed(mut self, name: &str, version: &str) -> Self {
        drop(
            self.system
                .installed
                .insert(name.to_owned(), version.to_owned()),
        );
        self
    }

    /// Offers `version` as the upgrade of the installed package `name`.
    #[inline]
    #[must_use]
    pub fn upgradable(mut self, name: &str, version: &str) -> Self {
        drop(
            self.system
                .upgradable
                .insert(name.to_owned(), version.to_owned()),
        );
        self
    }

    /// Adds a package the feed offers for installation.
    #[inline]
    #[must_use]
    pub fn installable(mut self, name: &str, version: &str) -> Self {
        drop(
            self.system
                .installable
                .insert(name.to_owned(), version.to_owned()),
        );
        self
    }

    /// Adds the init script `/opt/etc/init.d/<name>`.
    #[inline]
    #[must_use]
    pub fn service(mut self, name: &str, service: Service) -> Self {
        drop(self.system.services.insert(name.to_owned(), service));
        self
    }

    /// Replaces the listening address (default `127.0.0.1:0`).
    #[inline]
    #[must_use]
    pub const fn bind(mut self, address: SocketAddr) -> Self {
        self.bind = address;
        self
    }
}

/// Mutable state of a running fake.
struct State {
    /// Current host key; a new connection uses the key current at accept time.
    host_key: PrivateKey,
    /// Accepted password.
    password: Zeroizing<String>,
    /// Packages, services and `authorized_keys`.
    system: System,
    /// Active fault switch.
    fault: Option<Fault>,
    /// Activity counters.
    counters: Counters,
}

/// State shared by the connections and the handle.
struct Shared {
    /// Guarded state.
    state: Mutex<State>,
}

impl Shared {
    /// Locks the state; a poisoned lock still holds consistent data.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A fresh random ed25519 host key.
fn host_key() -> PrivateKey {
    let seed = Zeroizing::new(rand::rng().random::<[u8; 32]>());
    PrivateKey::from(private::Ed25519Keypair::from_seed(&seed))
}

/// Entry point of the fake.
#[derive(Debug)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the fake is named after what it imitates"
)]
pub struct FakeEntwareSsh;

impl FakeEntwareSsh {
    /// Starts the fake on `config`'s address (default `127.0.0.1:0`) with a new random
    /// ed25519 host key.
    ///
    /// # Errors
    ///
    /// Returns listener binding errors.
    // cancel-safe: dropping before the bind completes leaves nothing running.
    #[inline]
    pub async fn spawn(config: Config) -> io::Result<(SocketAddr, Handle)> {
        let listener = TcpListener::bind(config.bind).await?;
        let address = listener.local_addr()?;
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                host_key: host_key(),
                password: config.password,
                system: config.system,
                fault: None,
                counters: Counters::default(),
            }),
        });
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(connection::serve(listener, Arc::clone(&shared), stopped));
        Ok((address, Handle { shared, stop, task }))
    }
}

/// Control handle of a running fake; dropping it stops the fake.
#[must_use = "dropping the handle stops the fake"]
pub struct Handle {
    /// State shared with the connections.
    shared: Arc<Shared>,
    /// Shutdown signal.
    stop: oneshot::Sender<()>,
    /// Accept loop; it owns the connection tasks.
    task: JoinHandle<()>,
}

impl fmt::Debug for Handle {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handle").finish_non_exhaustive()
    }
}

impl Handle {
    /// The public host key new connections see.
    #[inline]
    #[must_use]
    pub fn host_key(&self) -> PublicKey {
        self.shared.lock().host_key.public_key().clone()
    }

    /// Replaces the host key with a new random ed25519 key, as a reinstalled router
    /// would; returns the new public key. Open connections keep the old key.
    #[inline]
    #[must_use]
    pub fn replace_host_key(&self) -> PublicKey {
        let replacement = host_key();
        let public = replacement.public_key().clone();
        self.shared.lock().host_key = replacement;
        public
    }

    /// Snapshot of the activity counters.
    #[inline]
    #[must_use]
    pub fn counters(&self) -> Counters {
        self.shared.lock().counters
    }

    /// Sets or clears the fault switch.
    #[inline]
    pub fn set_fault(&self, fault: Option<Fault>) {
        self.shared.lock().fault = fault;
    }

    /// Current `authorized_keys` text.
    #[inline]
    #[must_use]
    pub fn authorized_keys(&self) -> String {
        self.shared.lock().system.authorized_keys.clone()
    }

    /// Installed packages: name to version.
    #[inline]
    #[must_use]
    pub fn installed(&self) -> BTreeMap<String, String> {
        self.shared.lock().system.installed.clone()
    }

    /// The service with init script `name`, if any.
    #[inline]
    #[must_use]
    pub fn service(&self, name: &str) -> Option<Service> {
        self.shared.lock().system.services.get(name).cloned()
    }

    /// Stops accepting, drops every connection and waits for the accept loop.
    ///
    /// # Errors
    ///
    /// Returns the accept loop's join error.
    // NOT cancel-safe: after signaling shutdown, cancellation loses the join result.
    #[inline]
    pub async fn shutdown(self) -> io::Result<()> {
        match self.stop.send(()) {
            Ok(()) | Err(()) => {}
        }
        self.task.await.map_err(io::Error::other)
    }
}
