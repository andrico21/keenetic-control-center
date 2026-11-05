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

mod config_state;
mod failsafe;
mod fixtures;
pub mod model;
pub mod ndw2;
mod server;
pub mod time;
mod tree;

use alloc::{collections::BTreeSet, sync::Arc};
use core::{error::Error, fmt, net::SocketAddr, time::Duration};
use std::io;

use axum::http::HeaderValue;
use kcc_config::config_text::ParseError;
use serde_json::Value;
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
}

impl FaultInjection {
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
        let (settings, show, startup_config) =
            fixtures::load(self.profile, &title, &release).map_err(BuildError::Fixture)?;
        let config = config_state::ConfigState::new(startup_config, model.hw_id(), &title)
            .map_err(BuildError::ConfigFixture)?;
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
        let (stop, stopped) = oneshot::channel::<()>();
        let app = self.router();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    match stopped.await {
                        Ok(()) | Err(_) => {}
                    }
                })
                .await
        });
        Ok((local, Handle { stop, task }))
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
}

/// A running server; dropping it also stops the server.
#[derive(Debug)]
#[must_use = "dropping the handle stops the server"]
pub struct Handle {
    /// Signals graceful shutdown.
    stop: oneshot::Sender<()>,
    /// The serving task.
    task: JoinHandle<io::Result<()>>,
}

impl Handle {
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
