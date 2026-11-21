//! Shared test fixtures and fake router helpers.
//!
//! [`FakeRouter`] simulates the HTTP surface of a KeeneticOS/NetcrazeOS router: the
//! `x-ndw2-interactive` login on `/auth`, the RCI settings tree on `/rci/`, and `show`
//! responses served from per-model fixtures. Behaviour that is not taken from captured
//! router traffic is listed in `BEHAVIOUR.md` next to this crate's manifest.
//!
//! ```no_run
//! # async fn demo() -> std::io::Result<()> {
//! let (addr, handle) = kcc_testkit::FakeRouter::spawn().await?;
//! // talk to http://{addr}/auth ...
//! handle.shutdown().await
//! # }
//! ```
// `dead_code_pub_in_binary` fires on the public API only in the lib unit-test
// binary; rustc accepts an expect for it at crate level alone.
#![cfg_attr(
    test,
    expect(
        dead_code_pub_in_binary,
        reason = "public API: unused inside the unit-test harness"
    )
)]

extern crate alloc;

pub mod anonymize;
pub mod auth_fixture;
mod auth_fixture_digest;
mod auth_fixture_ndw4;
pub mod blocking_gate;
pub mod bracket;
pub mod capture;
mod cli_engine;
mod components;
mod config_state;
mod connection_fault;
pub mod entware_ssh;
mod failsafe;
pub mod fake_elasticsearch;
pub mod fake_loki;
pub mod fake_telegram;
pub mod firmware_update;
mod fixtures;
mod inflight;
pub mod leak;
pub mod live_matrix;
#[cfg(unix)]
mod local_socket;
pub mod migration;
pub mod model;
pub mod ndw2;
mod ntp;
pub mod outbound;
mod projection;
mod server;
pub mod stall;
pub mod time;
pub mod toml_text;
mod tree;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use core::{
    error::Error,
    fmt,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

use axum::{
    http::{HeaderValue, Method},
    serve::Listener as AxumListener,
};
use kcc_config::config_text::ParseError;
use serde_json::Value;
#[cfg(unix)]
use tokio::runtime;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use zeroize::Zeroizing;

use crate::{
    model::Profile,
    server::{Account, Shared},
    time::{Clock, SystemClock},
};

/// Login of the user created when the builder is given none.
pub const DEFAULT_LOGIN: &str = "admin";

/// Password of the user created when the builder is given none.
pub const DEFAULT_PASSWORD: &str = "admin";

/// Default session lifetime, matching `Max-Age=300` on real routers.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(300);

/// Largest accepted request body in bytes; larger bodies get 413.
pub const MAX_BODY_BYTES: usize = server::MAX_BODY_BYTES;

/// Writes `contents` to `dir/name` readable by its owner only (mode 0600 on unix), as
/// kcc requires of every secret file it reads, and returns the path.
///
/// # Errors
///
/// Returns the I/O error of the write or the permission change.
#[inline]
pub fn write_secret_file(dir: &Path, name: &str, contents: &str) -> io::Result<PathBuf> {
    let path = dir.join(name);
    fs::write(&path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(path)
}

/// Per-instance fault injection controls for workflow tests.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct FaultInjection {
    /// RCI paths whose writes acknowledge but do not mutate state.
    silent_noop_paths: BTreeSet<String>,
    /// Return HTTP 500 after this many requests have completed normally.
    fail_after_requests: Option<u64>,
    /// Artificial delay before each request.
    latency: Duration,
    /// Clear all sessions after this many authenticated requests.
    session_drop_after_requests: Option<u64>,
    /// Refuse attempts to take the management bridge down.
    refuse_management_bridge_down: bool,
    /// Parser substrings, each with its bounded number of matching failures.
    fail_parse_matching: Vec<(String, usize)>,
    /// Read substrings, each with its bounded number of matching HTTP 500 answers.
    fail_read_matching: Vec<(String, usize)>,
    /// Whether one single-route removal wipes every static route in that address family.
    route_wipe_on_remove: bool,
    /// Acknowledge `fail-safe timer reboot` without arming the timer.
    fail_safe_arm_noop: bool,
    /// Root batch items containing this JSON pointer return an error without applying.
    refuse_batch_pointer: Option<String>,
    /// Show resources whose `GET` answers 404 while `POST` answers normally.
    show_requires_post: BTreeSet<String>,
    /// Show resources whose `GET` answers 405 while `POST` answers normally.
    show_get_not_allowed: BTreeSet<String>,
    /// Answers left out at the end of every root batch reply.
    batch_answers_dropped: usize,
    /// Parser command whose connection is lost before or after application.
    disconnect_parse: Option<(String, bool)>,
    /// `show version` probes answered after `components commit` before the reboot window.
    components_commit_answers: u32,
    /// What the restart after `components commit` does with the staged changes.
    components_restart: components::Restart,
}

impl FaultInjection {
    /// Drops connections after applying a matching parser command.
    #[inline]
    #[must_use]
    pub fn disconnect_after_parse(mut self, command: String) -> Self {
        self.disconnect_parse = Some((command, true));
        self
    }

    /// Drops connections without applying a matching parser command.
    #[inline]
    #[must_use]
    pub fn disconnect_before_parse(mut self, command: String) -> Self {
        self.disconnect_parse = Some((command, false));
        self
    }
    /// Refuses matching root batch items inside the normal HTTP 200 response.
    #[inline]
    #[must_use]
    pub fn refuse_batch_pointer(mut self, pointer: String) -> Self {
        self.refuse_batch_pointer = Some(pointer);
        self
    }

    /// Answers `GET /rci/<path>` for the show resource `path` (for example
    /// `show/clock/date`) with 404, as a router that serves it only by `POST` does;
    /// `POST /rci/<path>` still answers normally.
    #[inline]
    #[must_use]
    pub fn show_requires_post<S>(mut self, path: S) -> Self
    where
        S: Into<String>,
    {
        let _: bool = self.show_requires_post.insert(path.into());
        self
    }

    /// Answers `GET /rci/<path>` for the show resource `path` with 405 Method Not Allowed;
    /// `POST /rci/<path>` still answers normally.
    #[inline]
    #[must_use]
    pub fn show_get_not_allowed<S>(mut self, path: S) -> Self
    where
        S: Into<String>,
    {
        let _: bool = self.show_get_not_allowed.insert(path.into());
        self
    }

    /// Answers every root batch with one element fewer than it had items: the last
    /// item is applied but its answer is missing.
    #[inline]
    #[must_use]
    pub const fn short_batch_reply(mut self) -> Self {
        self.batch_answers_dropped = 1;
        self
    }

    /// Adds one RCI path whose writes become acknowledged no-ops.
    #[inline]
    #[must_use]
    pub fn silent_noop_path<S>(mut self, path: S) -> Self
    where
        S: Into<String>,
    {
        let _: bool = self.silent_noop_paths.insert(path.into());
        self
    }

    /// Starts returning HTTP 500 after `count` requests.
    #[inline]
    #[must_use]
    pub const fn fail_after_requests(mut self, count: u64) -> Self {
        self.fail_after_requests = Some(count);
        self
    }

    /// Adds artificial request latency.
    #[inline]
    #[must_use]
    pub const fn latency(mut self, latency: Duration) -> Self {
        self.latency = latency;
        self
    }

    /// Drops every session after `count` authenticated requests.
    #[inline]
    #[must_use]
    pub const fn session_drop_after_requests(mut self, count: u64) -> Self {
        self.session_drop_after_requests = Some(count);
        self
    }

    /// Refuses `interface Bridge0 down` parser commands.
    #[inline]
    #[must_use]
    pub const fn refuse_management_bridge_down(mut self, enabled: bool) -> Self {
        self.refuse_management_bridge_down = enabled;
        self
    }

    /// Makes the next `times` parser lines containing `substring` return an RCI error.
    ///
    /// Calls accumulate: each substring keeps its own count, and a line is rejected by the
    /// first substring it contains that still has failures left.
    #[inline]
    #[must_use]
    pub fn fail_parse_matching<S>(mut self, substring: S, times: usize) -> Self
    where
        S: Into<String>,
    {
        self.fail_parse_matching.push((substring.into(), times));
        self
    }

    /// Answers the next `times` reads containing `substring` with HTTP 500: a `show`
    /// path such as `show/media`, the body of a root `POST` such as `"rc":{"user"`, or a
    /// configuration file name such as `running-config.txt`. Parser lines are never matched.
    #[inline]
    #[must_use]
    pub fn fail_read_matching<S>(mut self, substring: S, times: usize) -> Self
    where
        S: Into<String>,
    {
        self.fail_read_matching.push((substring.into(), times));
        self
    }

    /// Arms the simulated incident where one route removal wipes its static route family.
    #[inline]
    #[must_use]
    pub const fn route_wipe_on_remove(mut self, enabled: bool) -> Self {
        self.route_wipe_on_remove = enabled;
        self
    }

    /// Acknowledges `system configuration fail-safe timer reboot <s>` as armed while the
    /// timer stays off, so `show last-change` keeps reporting it inactive.
    #[inline]
    #[must_use]
    pub const fn fail_safe_arm_noop(mut self, enabled: bool) -> Self {
        self.fail_safe_arm_noop = enabled;
        self
    }

    /// Keeps answering after `components commit` until `probes` `show version` reads were
    /// answered, as a real router does while it downloads and flashes, and starts the
    /// reboot window at the next one.
    #[inline]
    #[must_use]
    pub const fn components_commit_answers(mut self, probes: u32) -> Self {
        self.components_commit_answers = probes;
        self
    }

    /// Restarts after `components commit` without applying the staged component changes,
    /// as after a failed flash.
    #[inline]
    #[must_use]
    pub const fn components_commit_discards(mut self, enabled: bool) -> Self {
        self.components_restart = if enabled {
            components::Restart::Discards
        } else {
            components::Restart::Applies
        };
        self
    }
}

/// Sanitized metadata for one request observed by a fake router.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RequestRecord {
    /// HTTP method.
    method: Method,
    /// URI path without a query string.
    path: String,
    /// Query pairs sorted by key and value.
    query: Vec<(String, String)>,
    /// Root parser lines in body order; `None` for a line with a secret-bearing field.
    commands: Vec<Option<String>>,
}

impl RequestRecord {
    /// Returns the HTTP method.
    #[inline]
    #[must_use]
    pub const fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the URI path without a query string.
    #[inline]
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns sorted query pairs.
    #[inline]
    #[must_use]
    pub fn query(&self) -> &[(String, String)] {
        &self.query
    }

    /// Returns the last parser line of this request when it contains no secret-bearing
    /// command field; see [`Self::commands`] for every line of a batch.
    #[inline]
    #[must_use]
    pub fn command(&self) -> Option<&str> {
        self.commands.last().and_then(Option::as_deref)
    }

    /// Returns every root parser line of this request in body order, `None` for a line
    /// that contains a secret-bearing command field.
    #[inline]
    pub fn commands(&self) -> impl Iterator<Item = Option<&str>> {
        self.commands.iter().map(Option::as_deref)
    }
}

/// A user to create on the fake router.
#[derive(Clone)]
struct UserSpec {
    /// Login name.
    login: String,
    /// Plain password; hashed with the realm at build time.
    password: Zeroizing<String>,
    /// Tags reported by `whoami`.
    tags: Vec<String>,
}

impl fmt::Debug for UserSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserSpec")
            .field("login", &self.login)
            .field("password", &"[REDACTED]")
            .field("tags", &self.tags)
            .finish()
    }
}

/// Configures a [`FakeRouter`].
#[derive(Debug, Clone)]
#[must_use]
pub struct FakeRouterBuilder {
    /// Model and firmware line.
    profile: Profile,
    /// Realm override.
    realm: Option<String>,
    /// `show version` title override.
    title: Option<String>,
    /// `show version` release override.
    release: Option<String>,
    /// Users; empty means one default admin.
    users: Vec<UserSpec>,
    /// Session lifetime.
    ttl: Duration,
    /// Time source.
    clock: Arc<dyn Clock>,
    /// Fault injection controls.
    faults: FaultInjection,
    /// Per-path show fixture replacements for focused integration scenarios.
    show_overrides: BTreeMap<String, Value>,
    /// Whether an interface owns the loopback address the fake is reached on.
    reached_directly: bool,
}

impl FakeRouterBuilder {
    /// Overrides the authentication realm (default: the model's realm).
    #[inline]
    pub fn realm<S>(mut self, realm: S) -> Self
    where
        S: Into<String>,
    {
        self.realm = Some(realm.into());
        self
    }

    /// Overrides the firmware `title` and `release` reported by `show version`.
    #[inline]
    pub fn firmware<T, R>(mut self, title: T, release: R) -> Self
    where
        T: Into<String>,
        R: Into<String>,
    {
        self.title = Some(title.into());
        self.release = Some(release.into());
        self
    }

    /// Adds a user with `password` and `tags`.
    #[inline]
    pub fn user<L, P, I>(mut self, login: L, password: P, tags: I) -> Self
    where
        L: Into<String>,
        P: Into<String>,
        I: IntoIterator,
        I::Item: Into<String>,
    {
        self.users.push(UserSpec {
            login: login.into(),
            password: Zeroizing::new(password.into()),
            tags: tags.into_iter().map(Into::into).collect(),
        });
        self
    }

    /// Sets the session lifetime (default [`DEFAULT_SESSION_TTL`]).
    #[inline]
    pub const fn session_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Replaces the time source, e.g. with a [`time::MockClock`].
    #[inline]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Replaces the per-instance fault injection controls.
    #[inline]
    pub fn faults(mut self, faults: FaultInjection) -> Self {
        self.faults = faults;
        self
    }

    /// Replaces one embedded `show` fixture at `path`.
    #[inline]
    pub fn show_fixture<S>(mut self, path: S, value: Value) -> Self
    where
        S: Into<String>,
    {
        drop(self.show_overrides.insert(path.into(), value));
        self
    }

    /// Lists `Loopback0` owning `127.0.0.1`, the address the fake is reached on, as a router
    /// kcc reaches directly lists the interface whose address kcc connects to.
    ///
    /// Without it no interface owns that address, as on a router kcc reaches through address
    /// translation or a relay, so kcc cannot tell which interface carries its connection. An
    /// `interface` [`show_fixture`](Self::show_fixture) replaces the whole list either way.
    #[inline]
    pub const fn reached_directly(mut self) -> Self {
        self.reached_directly = true;
        self
    }

    /// Builds the router state from the profile's fixtures.
    ///
    /// # Errors
    ///
    /// [`BuildError`] when the realm is not a valid header value or an embedded fixture
    /// does not parse.
    #[inline]
    pub fn build(self) -> Result<FakeRouter, BuildError> {
        let model = self.profile.model();
        let firmware = self.profile.firmware();
        let realm = self.realm.unwrap_or_else(|| model.realm().to_owned());
        if realm.contains('"') || HeaderValue::from_str(&realm).is_err() {
            return Err(BuildError::InvalidRealm);
        }
        let title = self.title.unwrap_or_else(|| firmware.title().to_owned());
        let release = self
            .release
            .unwrap_or_else(|| firmware.release().to_owned());
        let (settings, mut show, startup_config) =
            fixtures::load(self.profile, &title, &release).map_err(BuildError::Fixture)?;
        if self.reached_directly
            && let Some(Value::Object(interfaces)) = show.get_mut("interface")
        {
            drop(interfaces.insert(
                "Loopback0".to_owned(),
                serde_json::json!({"id":"Loopback0","interface-name":"Loopback0","type":"Loopback",
                    "link":"up","state":"up","address":Ipv4Addr::LOCALHOST.to_string(),"mask":"255.0.0.0"}),
            ));
        }
        for (path, value) in self.show_overrides {
            drop(show.insert(path, value));
        }
        let mut config = config_state::ConfigState::new(startup_config, model.hw_id(), &title)
            .map_err(BuildError::ConfigFixture)?;
        config.seed_membership(&settings);
        let mut users = self.users;
        if users.is_empty() {
            users.push(UserSpec {
                login: DEFAULT_LOGIN.to_owned(),
                password: Zeroizing::new(DEFAULT_PASSWORD.to_owned()),
                tags: vec!["cli".to_owned(), "http-proxy".to_owned()],
            });
        }
        let accounts = users
            .into_iter()
            .map(|user| {
                let ha1 = ndw2::ha1(&user.login, &realm, &user.password);
                Account::new(user.login, ha1, user.tags)
            })
            .collect();
        let shared = Shared::new(
            server::random_upper(12),
            realm,
            model.product().to_owned(),
            accounts,
            self.ttl,
            self.clock,
            settings,
            show,
            config,
            self.faults,
        );
        Ok(FakeRouter {
            shared: Arc::new(shared),
        })
    }
}

/// Why a [`FakeRouterBuilder`] could not build.
#[derive(Debug)]
#[non_exhaustive]
pub enum BuildError {
    /// The realm contains `"` or is not a valid HTTP header value.
    InvalidRealm,
    /// An embedded fixture does not parse.
    Fixture(serde_json::Error),
    /// An embedded startup configuration does not parse.
    ConfigFixture(ParseError),
}

impl fmt::Display for BuildError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRealm => f.write_str("realm is not a valid header value"),
            Self::Fixture(_) => f.write_str("embedded fixture does not parse"),
            Self::ConfigFixture(_) => f.write_str("embedded startup configuration does not parse"),
        }
    }
}

impl Error for BuildError {
    #[inline]
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRealm => None,
            Self::Fixture(source) => Some(source),
            Self::ConfigFixture(source) => Some(source),
        }
    }
}

/// An in-memory fake router; clones share state.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FakeRouter {
    /// State shared with the handlers.
    shared: Arc<Shared>,
}

impl FakeRouter {
    /// Enables opt-in migration scenarios without altering ordinary model fixtures.
    #[inline]
    #[must_use]
    pub fn with_migration(self, fixture: migration::Fixture) -> Self {
        self.shared.configure_migration(fixture);
        self
    }

    /// Answers `components check-update` with `update` (by default the command is
    /// unknown to the fake).
    #[inline]
    #[must_use]
    pub fn with_firmware_update(self, update: firmware_update::FirmwareUpdate) -> Self {
        self.shared.configure_firmware_update(update);
        self
    }

    /// A builder for `profile` with defaults: model realm, profile firmware, one
    /// `admin`/`admin` user, 300 s sessions and the system clock.
    #[inline]
    pub fn builder(profile: Profile) -> FakeRouterBuilder {
        FakeRouterBuilder {
            profile,
            realm: None,
            title: None,
            release: None,
            users: Vec::new(),
            ttl: DEFAULT_SESSION_TTL,
            clock: Arc::new(SystemClock::new()),
            faults: FaultInjection::default(),
            show_overrides: BTreeMap::new(),
            reached_directly: false,
        }
    }

    /// Spawns the default router (`KN-1811`, 5.1) on an ephemeral loopback port.
    ///
    /// # Errors
    ///
    /// I/O errors from binding the listener; a fixture error is reported as
    /// [`io::ErrorKind::InvalidData`].
    // cancel-safe: dropping the future before the bind completes leaves nothing running.
    #[inline]
    pub async fn spawn() -> io::Result<(SocketAddr, Handle)> {
        let router = Self::builder(Profile::default())
            .build()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        router.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await
    }

    /// Serves this router on `addr` in a background task.
    ///
    /// # Errors
    ///
    /// I/O errors from binding the listener.
    // cancel-safe: dropping the future before the bind completes leaves nothing running.
    #[inline]
    pub async fn serve(self, addr: SocketAddr) -> io::Result<(SocketAddr, Handle)> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        Ok((local, self.serve_on(listener, ())))
    }

    /// Serves this router on a Unix socket in a fresh private temporary directory, for
    /// tests under a paused tokio clock, and returns a loopback TCP address for the router
    /// profile's URL, the socket's path and the handle.
    ///
    /// The client dials the socket for that address through
    /// `kcc_rci::OutboundPolicy::with_local_socket` (or the registry's hook of the same
    /// name). Unix sockets deliver within the sender's write, so a paused clock cannot
    /// jump over a reply that is written but not yet readable, as it can over loopback TCP
    /// on macOS.
    ///
    /// The TCP address still answers: a relay passes every connection on to the socket and
    /// delays each chunk by 2 ms. That delay is a deliberate network fault of the fake, not
    /// a wait: it makes a paused-clock client that bypasses the socket fail on Linux as it
    /// would on macOS. Never remove it to make a test pass.
    ///
    /// Must be called inside a tokio runtime. Stopping or dropping the handle stops both
    /// listeners and removes the directory.
    ///
    /// # Errors
    ///
    /// I/O errors from creating the directory or binding either listener, or an
    /// [`io::ErrorKind::Other`] error outside a tokio runtime.
    #[cfg(unix)]
    #[inline]
    pub fn serve_local(self) -> io::Result<(SocketAddr, PathBuf, Handle)> {
        drop(runtime::Handle::try_current().map_err(io::Error::other)?);
        let (listener, transport) = local_socket::Transport::bind()?;
        let (address, socket) = (transport.address(), transport.socket());
        Ok((address, socket, self.serve_on(listener, transport)))
    }

    /// Serves this router on `listener` with the management-outage fault until the
    /// handle stops it, then drops `transport`.
    fn serve_on<L, T>(self, listener: L, transport: T) -> Handle
    where
        L: AxumListener,
        L::Addr: fmt::Debug,
        T: Send + 'static,
    {
        let (stop, stopped) = oneshot::channel::<()>();
        let shared = Arc::clone(&self.shared);
        let app = self.router();
        let task = tokio::spawn(async move {
            let served = axum::serve(
                connection_fault::Listener::new(listener, self.shared.connection_lost()),
                app,
            )
            .with_graceful_shutdown(async move {
                match stopped.await {
                    Ok(()) | Err(_) => {}
                }
            })
            .await;
            drop(transport);
            served
        });
        Handle {
            router: Some(shared),
            stop,
            task,
        }
    }

    /// The axum router, for in-process requests without a socket.
    #[inline]
    pub fn router(&self) -> axum::Router {
        server::router(Arc::clone(&self.shared))
    }

    /// The session cookie name, random per instance.
    #[inline]
    #[must_use]
    pub fn cookie_name(&self) -> &str {
        self.shared.cookie_name()
    }

    /// The authentication realm.
    #[inline]
    #[must_use]
    pub fn realm(&self) -> &str {
        self.shared.realm()
    }

    /// A snapshot of the settings tree.
    #[inline]
    #[must_use]
    pub fn settings(&self) -> Value {
        self.shared.settings()
    }

    /// Returns the number of background processes stopped through DELETE.
    #[inline]
    #[must_use]
    pub fn stopped_processes(&self) -> u64 {
        self.shared.stopped_processes()
    }

    /// Returns the number of HTTP requests observed by this router.
    #[inline]
    #[must_use]
    pub fn request_count(&self) -> u64 {
        self.shared.request_count()
    }

    /// Inserts or replaces one router log record for subsequent snapshot or stream reads.
    #[inline]
    pub fn insert_log(&self, id: u64, record: Value) {
        self.shared.insert_log(id, record);
    }

    /// Returns the number of background `show log` streams started.
    #[inline]
    #[must_use]
    pub fn log_streams(&self) -> u64 {
        self.shared.log_streams()
    }
}

/// A running server; dropping it also stops the server.
#[derive(Debug)]
#[must_use = "dropping the handle stops the server"]
pub struct Handle {
    /// Main-router state; isolated authentication fixtures have none.
    router: Option<Arc<Shared>>,
    /// Signals graceful shutdown.
    stop: oneshot::Sender<()>,
    /// The serving task.
    task: JoinHandle<io::Result<()>>,
}

impl Handle {
    /// Whether either simulated recovery timer remains armed.
    #[inline]
    #[must_use]
    pub fn recovery_armed(&self) -> bool {
        self.router
            .as_ref()
            .is_some_and(|shared| shared.recovery_armed())
    }
    /// Returns peak simultaneous HTTP handlers, including injected latency and authentication.
    #[inline]
    #[must_use]
    pub fn max_concurrent(&self) -> usize {
        self.router
            .as_ref()
            .map_or(0, |shared| shared.max_concurrent())
    }

    /// Returns the number of HTTP requests observed by this router.
    #[inline]
    #[must_use]
    pub fn request_count(&self) -> u64 {
        self.router
            .as_ref()
            .map_or(0, |shared| shared.request_count())
    }

    /// Inserts or replaces one router log record for subsequent snapshot or stream reads.
    #[inline]
    pub fn insert_log(&self, id: u64, record: Value) {
        if let Some(shared) = &self.router {
            shared.insert_log(id, record);
        }
    }

    /// Returns the number of background `show log` streams started.
    #[inline]
    #[must_use]
    pub fn log_streams(&self) -> u64 {
        self.router
            .as_ref()
            .map_or(0, |shared| shared.log_streams())
    }

    /// Holds every request that reaches this router from now on, unanswered, until the
    /// returned [`stall::Stall`] is dropped.
    #[inline]
    pub fn stall(&self) -> stall::Stall {
        stall::Stall::new(self.router.as_ref().map(|shared| shared.gate()))
    }

    /// Returns sanitized metadata for every request observed by the server.
    #[inline]
    #[must_use]
    pub fn request_log(&self) -> Vec<RequestRecord> {
        self.router
            .as_ref()
            .map_or_else(Vec::new, |shared| shared.request_log())
    }

    /// Resolves once at least `at_least` requests used `method` on `path`, without polling.
    ///
    /// Callers bound the wait with their own timeout.
    // cancel-safe: only observes the request log.
    #[inline]
    pub async fn wait_for_requests(&self, method: &str, path: &str, at_least: usize) {
        if let Some(shared) = &self.router {
            shared.wait_for_requests(method, path, at_least).await;
        }
    }

    /// Returns a snapshot of the independent JSON settings tree.
    #[inline]
    #[must_use]
    pub fn settings_snapshot(&self) -> Value {
        self.router.as_ref().map_or_else(
            || Value::Object(serde_json::Map::new()),
            |shared| shared.settings(),
        )
    }

    /// Applies the configuration line `line` directly, as test setup: no request is logged
    /// and no fault applies. Returns whether the simulator accepted the line.
    #[inline]
    #[must_use]
    pub fn configure(&self, line: &str) -> bool {
        self.router
            .as_ref()
            .is_some_and(|shared| shared.configure(line))
    }

    /// Returns canonical running configuration text.
    #[inline]
    #[must_use]
    pub fn running_config_text(&self) -> String {
        self.router
            .as_ref()
            .map_or_else(String::new, |shared| shared.config_text(false))
    }

    /// Returns canonical startup configuration text.
    #[inline]
    #[must_use]
    pub fn startup_config_text(&self) -> String {
        self.router
            .as_ref()
            .map_or_else(String::new, |shared| shared.config_text(true))
    }

    /// Stops the server and waits for it to finish.
    ///
    /// # Errors
    ///
    /// The server's I/O error, or an [`io::ErrorKind::Other`] error if the task panicked.
    // NOT cancel-safe: if dropped after the stop signal, the server still shuts down but
    // its result is lost.
    #[inline]
    pub async fn shutdown(self) -> io::Result<()> {
        match self.stop.send(()) {
            Ok(()) | Err(()) => {}
        }
        self.task.await.map_err(io::Error::other)?
    }
}
