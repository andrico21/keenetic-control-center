//! Applies what other processes change in `api_keys.json` and `users.json` (the CLI, an
//! edited or restored state file) to the running server within one poll interval.
//!
//! The same pass tells the [`Follower`]s registered with [`StateWatch::with_follower`] to
//! reload once when any of their files changed (the notifier's `notify.json` and sealed
//! bot token, the scheduler's `schedules.json`).
//!
//! Each file is checked by inode, modification time and size, and only then by content:
//! a key set (name, hash, role) that differs is reloaded into the MCP transport, and the
//! Web sessions whose account is gone, disabled, holds another role or has another
//! password end. A rewrite that changes none of that (a key's `last_used`, a sign-in's
//! failure counter) reloads nothing. A file that cannot be read keeps the last good state
//! and is retried on the next pass. A SIGHUP runs the same pass for both files and reloads every follower.

mod follow;
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions are not rendered API documentation"
)]
mod tests;

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
#[cfg(unix)]
use core::future::pending;
use core::{fmt::Display, time::Duration};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
use std::{fs, io, path::Path, time::UNIX_EPOCH};

pub(crate) use follow::Follower;
use follow::{Followers, observe_all};
use kcc_app::{
    accounts::{UsersDocument, standing::AccountStanding},
    api_keys::ApiKeysDocument,
    persist::{StateDoc as _, StateStore},
};
use kcc_web::{
    WebState,
    admin::{AuthReload as _, TransportReload},
};
#[cfg(unix)]
use tokio::signal::unix::Signal;
use tokio::{
    task::spawn_blocking,
    time::{Interval, MissedTickBehavior, interval},
};

/// How often the state files are checked.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Log target of a change that was applied.
const RELOAD: &str = "kcc::state_reload";

/// Log target of the watcher's other observations.
const WATCH: &str = "kcc::state_watch";

/// What started a pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Trigger {
    /// Server start: record both files and install the keys once, logging no reload.
    Start,
    /// The poll interval: act on files that changed on disk.
    Tick,
    /// SIGHUP: re-read and apply both files.
    #[cfg(unix)]
    Hangup,
}

/// A state file's identity on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Version {
    /// The file does not exist.
    Missing,
    /// The file exists.
    Present {
        /// Inode number (0 where the platform has none).
        inode: u64,
        /// Modification time since the Unix epoch, to the nanosecond.
        modified: Option<Duration>,
        /// Length in bytes.
        size: u64,
    },
    /// The file's metadata cannot be read.
    Unreadable(io::ErrorKind),
}

/// The keys as the transport authenticates them: name, hash, role and expiry.
type KeySet = BTreeSet<(String, String, String, Option<u64>)>;

/// Every account's standing by username.
type Standings = BTreeMap<String, AccountStanding>;

/// One watched file.
#[derive(Debug, Default)]
struct Tracked<T> {
    /// The version whose content is applied.
    applied: Option<Version>,
    /// The version last warned about.
    warned: Option<Version>,
    /// The applied content.
    content: T,
}

impl<T> Tracked<T> {
    /// Whether a `trigger` pass reads the file at `version`.
    fn due(&self, trigger: Trigger, version: Version) -> bool {
        match trigger {
            Trigger::Tick => self.applied != Some(version),
            #[cfg(unix)]
            Trigger::Start | Trigger::Hangup => true,
            #[cfg(not(unix))]
            Trigger::Start => true,
        }
    }

    /// Records `content` as applied at `version`.
    fn apply(&mut self, version: Version, content: T) {
        self.applied = Some(version);
        self.warned = None;
        self.content = content;
    }

    /// Warns once per version of `file` that could not be applied; the next pass
    /// retries it.
    fn failed(&mut self, file: &'static str, version: Version, error: &dyn Display) {
        if self.warned != Some(version) {
            tracing::warn!(target: WATCH, file, %error, "state file not applied; the last good state stays active");
            self.warned = Some(version);
        }
    }
}

/// The watcher of one server's key, account and follower files.
#[derive(Debug)]
pub(crate) struct StateWatch {
    /// State directory holding both files.
    state: StateStore,
    /// The MCP transport's key reload, the one the Web keys page uses.
    transport: Arc<TransportReload>,
    /// The Web UI whose sessions follow the accounts, when it is enabled.
    web: Option<WebState>,
    /// `api_keys.json`.
    keys: Tracked<KeySet>,
    /// `users.json`.
    users: Tracked<Standings>,
    /// The components that follow further state files.
    followers: Followers,
}

impl StateWatch {
    /// A watcher reloading keys through `transport` and ending `web`'s stale sessions.
    pub(crate) fn new(transport: Arc<TransportReload>, web: Option<WebState>) -> Self {
        Self {
            state: transport.state().clone(),
            transport,
            web,
            keys: Tracked::default(),
            users: Tracked::default(),
            followers: Followers::default(),
        }
    }

    /// Also watches `files` (relative to the state directory): `follower` reloads once
    /// per pass in which any of them changed, and on SIGHUP.
    pub(crate) fn with_follower(
        mut self,
        files: &'static [&'static str],
        follower: Arc<dyn Follower>,
    ) -> Self {
        self.followers.add(files, follower);
        self
    }

    /// The MCP transport's reload bridge, for the SIGHUP reload.
    #[cfg(unix)]
    pub(crate) const fn transport(&self) -> &Arc<TransportReload> {
        &self.transport
    }

    /// Checks both files every [`POLL_INTERVAL`] until the runtime stops; each SIGHUP on
    /// `signals` applies both files, then runs `reload` for the rest of the configuration.
    // cancel-safe: every pass either records what it applied or leaves the file for the
    // next pass, and key installs and session ends are idempotent.
    #[cfg(unix)]
    pub(crate) async fn run<F, R>(mut self, signals: io::Result<Signal>, mut reload: F)
    where
        F: FnMut() -> R,
        R: Future<Output = ()>,
    {
        let mut hangups = match signals {
            Ok(stream) => Some(stream),
            Err(error) => {
                tracing::error!(%error, "cannot install SIGHUP reload handler");
                None
            }
        };
        self.start().await;
        let mut ticks = ticks();
        loop {
            tokio::select! {
                _instant = ticks.tick() => self.sync(Trigger::Tick).await,
                () = next_hangup(&mut hangups) => {
                    self.sync(Trigger::Hangup).await;
                    reload().await;
                }
            }
        }
    }

    /// Checks both files every [`POLL_INTERVAL`] until the runtime stops.
    // cancel-safe: as the Unix variant.
    #[cfg(not(unix))]
    pub(crate) async fn run(mut self) {
        self.start().await;
        let mut ticks = ticks();
        loop {
            let _instant = ticks.tick().await;
            self.sync(Trigger::Tick).await;
        }
    }

    /// Records both files as they are and installs the keys, so a change made while the
    /// server started is not missed.
    // cancel-safe: as `sync`.
    async fn start(&mut self) {
        self.sync(Trigger::Start).await;
        tracing::debug!(
            target: WATCH,
            interval_ms = POLL_INTERVAL.as_millis(),
            "state file watch started"
        );
    }

    /// One pass over both files.
    // cancel-safe: a pass dropped midway leaves its file unrecorded, so the next pass
    // applies it again.
    async fn sync(&mut self, trigger: Trigger) {
        let dir = self.state.dir().to_owned();
        let plan = self.followers.plan();
        let observed = spawn_blocking(move || {
            (
                observe(&dir.join(ApiKeysDocument::FILE_NAME)),
                observe(&dir.join(UsersDocument::FILE_NAME)),
                observe_all(&dir, &plan),
            )
        })
        .await;
        let Ok((keys, users, followed)) = observed.inspect_err(|error| {
            tracing::warn!(target: WATCH, %error, "state file check failed");
        }) else {
            return;
        };
        self.sync_keys(trigger, keys).await;
        if let Some(web) = self.web.clone() {
            self.sync_users(trigger, users, &web).await;
        }
        self.followers.apply(trigger, followed);
    }

    /// Reloads the keys when their set changed.
    // cancel-safe: as `sync`.
    async fn sync_keys(&mut self, trigger: Trigger, version: Version) {
        const FILE: &str = ApiKeysDocument::FILE_NAME;
        if !self.keys.due(trigger, version) {
            return;
        }
        if let Version::Unreadable(kind) = version {
            self.keys.failed(FILE, version, &io::Error::from(kind));
            return;
        }
        let state = self.state.clone();
        let set = match spawn_blocking(move || state.read::<ApiKeysDocument>()).await {
            Ok(Ok(document)) => key_set(document.unwrap_or_default()),
            Ok(Err(error)) => return self.keys.failed(FILE, version, &error),
            Err(error) => return self.keys.failed(FILE, version, &error),
        };
        if trigger == Trigger::Tick && set == self.keys.content {
            tracing::debug!(target: WATCH, file = FILE, "state file rewritten without a change");
            return self.keys.apply(version, set);
        }
        let transport = Arc::clone(&self.transport);
        match spawn_blocking(move || transport.reload_keys()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return self.keys.failed(FILE, version, &error),
            Err(error) => return self.keys.failed(FILE, version, &error),
        }
        if trigger != Trigger::Start {
            tracing::debug!(target: RELOAD, file = FILE, keys = set.len(), "API keys reloaded");
        }
        self.keys.apply(version, set);
    }

    /// Ends the Web sessions the accounts no longer back.
    // cancel-safe: as `sync`.
    async fn sync_users(&mut self, trigger: Trigger, version: Version, web: &WebState) {
        const FILE: &str = UsersDocument::FILE_NAME;
        if !self.users.due(trigger, version) {
            return;
        }
        if let Version::Unreadable(kind) = version {
            self.users.failed(FILE, version, &io::Error::from(kind));
            return;
        }
        let (standings, ended) = match web.end_stale_sessions().await {
            Ok(checked) => checked,
            Err(error) => return self.users.failed(FILE, version, &error),
        };
        warn_unopenable(&self.users.content, &standings);
        let changed = standings != self.users.content;
        match trigger {
            Trigger::Tick if !changed && ended == 0 => {
                tracing::debug!(target: WATCH, file = FILE, "state file rewritten without a change");
            }
            #[cfg(not(unix))]
            Trigger::Tick => {
                tracing::debug!(target: RELOAD, file = FILE, ended, "account changes applied");
            }
            #[cfg(unix)]
            Trigger::Tick | Trigger::Hangup => {
                tracing::debug!(target: RELOAD, file = FILE, ended, "account changes applied");
            }
            Trigger::Start => {}
        }
        self.users.apply(version, standings);
    }
}

/// The poll timer; a pass that overruns skips the ticks it missed.
fn ticks() -> Interval {
    let mut ticks = interval(POLL_INTERVAL);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticks
}

/// Waits for the next SIGHUP; forever when there is no handler or it closed.
// cancel-safe: `Signal::recv` is cancel-safe.
#[cfg(unix)]
async fn next_hangup(hangups: &mut Option<Signal>) {
    if let Some(signals) = hangups.as_mut()
        && signals.recv().await.is_some()
    {
        return;
    }
    *hangups = None;
    pending::<()>().await;
}

/// Warns once about each account in `standings` whose stored hash cannot be opened and
/// that changed since `previous`.
fn warn_unopenable(previous: &Standings, standings: &Standings) {
    for (account, standing) in standings {
        if standing.fingerprint.is_none() && previous.get(account) != Some(standing) {
            tracing::warn!(target: WATCH, account, "stored password hash cannot be opened; the account's sessions end");
        }
    }
}

/// The key set of `document`.
fn key_set(document: ApiKeysDocument) -> KeySet {
    document
        .keys
        .into_iter()
        .map(|key| (key.name, key.hash, key.role, key.expires_at))
        .collect()
}

/// `path`'s identity on disk.
fn observe(path: &Path) -> Version {
    match fs::metadata(path) {
        Ok(metadata) => Version::Present {
            inode: inode(&metadata),
            modified: metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok()),
            size: metadata.len(),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Version::Missing,
        Err(error) => Version::Unreadable(error.kind()),
    }
}

/// The inode of `metadata`'s file.
#[cfg(unix)]
fn inode(metadata: &fs::Metadata) -> u64 {
    metadata.ino()
}

/// No inode outside Unix; modification time and size identify the version.
#[cfg(not(unix))]
const fn inode(_metadata: &fs::Metadata) -> u64 {
    0
}
