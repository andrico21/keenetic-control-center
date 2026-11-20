//! Telegram notifications of `kcc serve`.
//!
//! The notifier starts with the server, whether or not notifications are on, and follows
//! `notify.json` and the sealed bot token: a change made on the Web page or with the CLI
//! takes effect within the state watcher's poll. It only observes: router poll results
//! (one follower per router while a router event is selected, which keeps every router
//! polled), this process's audit entries and the job runner's events, and renders each
//! line in the chosen language for the outbox, which merges, paces and delivers them.
//! Nothing about clients is persisted; the only memory kept across restarts is the
//! firmware version announced per router, in `notify_state.json`.

mod arrivals;
mod audits;
mod control;
mod current;
mod failed_jobs;
mod handle;
mod health;
mod memory;
mod render;
mod routers;
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]
mod tests;

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use std::sync::{Mutex, MutexGuard, PoisonError, RwLock};

use kcc_app::{
    accounts::{AccountStore, Clock},
    audit::AuditLog,
    jobs::JobRunner,
    notify_store::NotifyEvent,
    persist::StateStore,
    poller::Poller,
    registry::RouterRegistry,
    schedules::time::{ZoneName, format_local},
    secrets::MasterKey,
    settings::{Config, ConfigError, notifications::TelegramConfig},
};
use kcc_i18n::locale::Locale;
use kcc_telemetry::{
    metrics::instrumentation::SelfMetrics,
    notify::delivery::{Line, OutboxHandle, Timings},
};
use kcc_web::{fleet::UpdateCheck, fleet_updates::ComponentsUpdateCheck};
use tokio::{sync::watch, task::JoinHandle, time::Instant};

use self::{current::Current, failed_jobs::ScheduledJobs, memory::Firmware};
use crate::{server_error::ServerError, server_services::Services};

/// The state files the notifier follows, relative to the state directory.
pub(crate) const FILES: &[&str] = &["notify.json", "notify/telegram.token.sealed"];

/// Longest wait at shutdown for the lines still queued.
const FLUSH_WAIT: Duration = Duration::from_secs(2);

/// What the notifier reads and listens to.
pub(crate) struct Deps {
    /// The state directory.
    state: StateStore,
    /// Opens the sealed bot token.
    key: MasterKey,
    /// Router profiles and their changes.
    registry: Arc<RouterRegistry>,
    /// Router poll results.
    poller: Arc<Poller>,
    /// This process's audit writer.
    audit: AuditLog,
    /// Background jobs.
    jobs: Arc<JobRunner>,
    /// Web accounts, for lockout windows.
    accounts: Arc<AccountStore>,
    /// Cached firmware-update checks.
    updates: Arc<dyn UpdateCheck>,
    /// Wall clock.
    clock: Arc<dyn Clock>,
    /// Delivery metrics.
    metrics: Option<Arc<SelfMetrics>>,
}

impl Deps {
    /// The server's services.
    pub(crate) fn from_services(services: &Services) -> Self {
        Self {
            state: services.state.clone(),
            key: services.key.duplicate(),
            registry: Arc::clone(&services.registry),
            poller: Arc::clone(&services.poller),
            audit: services.audit.clone(),
            jobs: Arc::clone(&services.jobs),
            accounts: Arc::clone(&services.accounts),
            updates: Arc::<ComponentsUpdateCheck>::clone(&services.updates),
            clock: Arc::clone(&services.clock),
            metrics: services.metrics.clone(),
        }
    }
}

/// What the notifier takes from `kcc.toml`, read once at start.
pub(crate) struct Options {
    /// The Bot API address and trust anchor.
    telegram: TelegramConfig,
    /// The language when the settings name none (`[web] default_locale`).
    default_locale: Locale,
    /// The zone times are shown in (`[schedules] default_timezone`).
    zone: ZoneName,
    /// Delivery timing.
    timings: Timings,
}

impl Options {
    /// The notifier's part of `config`.
    ///
    /// # Errors
    ///
    /// [`ServerError::Config`] for a `[web] default_locale` or `[schedules]
    /// default_timezone` kcc does not know.
    pub(crate) fn from_config(config: &Config) -> Result<Self, ServerError> {
        Ok(Self {
            telegram: config.notify.telegram.clone(),
            default_locale: Locale::from_tag(&config.web.default_locale)
                .ok_or(ServerError::UnsupportedLocale)?,
            zone: ZoneName::parse(&config.schedules.default_timezone).map_err(|_unknown| {
                ConfigError::Invalid {
                    field: "schedules.default_timezone".to_owned(),
                    reason: "must be an IANA time zone name such as Europe/Berlin",
                }
            })?,
            timings: Timings::default(),
        })
    }
}

/// Locks `mutex`; a poisoned lock still holds consistent data here.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Everything the notifier's tasks share.
struct Shared {
    /// Delivery.
    outbox: OutboxHandle,
    /// The settings in force.
    current: Arc<RwLock<Current>>,
    /// The language when the settings name none.
    default_locale: Locale,
    /// The zone times are shown in.
    zone: ZoneName,
    /// Delivery timing; the merge window also delays job failures.
    timings: Timings,
    /// Sources.
    deps: Deps,
    /// Router id to the Unix time its offline and online messages are muted until.
    mutes: Mutex<BTreeMap<String, u64>>,
    /// Jobs the scheduler reports itself.
    scheduled: ScheduledJobs,
    /// The firmware announced per router.
    firmware: Mutex<Firmware>,
    /// Whether the audit writer's stop was reported.
    writer_stopped: AtomicBool,
    /// Asks the settings task to reload.
    reloads: Arc<watch::Sender<()>>,
    /// Whether router followers are wanted.
    watching: watch::Sender<bool>,
    /// The notifier's tasks, aborted at stop.
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Shared {
    /// The settings in force.
    fn current(&self) -> Current {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Installs new settings.
    fn replace(&self, current: Current) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = current;
    }

    /// Whether a line for `event` is sent.
    fn wants(&self, event: NotifyEvent) -> bool {
        self.current().wants(event)
    }

    /// The message language.
    fn locale(&self) -> Locale {
        self.current().locale()
    }

    /// Whether clients are named by name and MAC.
    fn client_details(&self) -> bool {
        self.current().client_details()
    }

    /// Queues the line `render` writes in the message language, when `event` is sent.
    fn emit<F>(&self, event: NotifyEvent, render: F)
    where
        F: FnOnce(Locale) -> String,
    {
        let current = self.current();
        if current.wants(event) {
            self.outbox
                .push(Line::new(render(current.locale()), Instant::now()));
        }
    }

    /// Mutes `router`'s offline and online messages until `until` (Unix seconds).
    fn mute(&self, router: &str, until: u64) {
        let _: &mut u64 = lock(&self.mutes)
            .entry(router.to_owned())
            .and_modify(|current| *current = (*current).max(until))
            .or_insert(until);
    }

    /// Whether `router` is muted at `now`; forgets expired mutes.
    fn muted(&self, router: &str, now: u64) -> bool {
        let mut mutes = lock(&self.mutes);
        mutes.retain(|_router, until| *until > now);
        mutes.contains_key(router)
    }

    /// `unix` as local time in the configured zone.
    fn local_time(&self, unix: u64) -> String {
        format_local(i64::try_from(unix).unwrap_or(i64::MAX), &self.zone)
    }

    /// Reports once that the audit writer stopped.
    fn writer_stopped(&self) {
        if !self.writer_stopped.swap(true, Ordering::AcqRel) {
            self.emit(NotifyEvent::AuditProblem, render::audit_stopped);
        }
    }
}

/// The running notifier; clones share it.
#[derive(Clone)]
pub(crate) struct NotifyHandle {
    /// The shared state.
    shared: Arc<Shared>,
}

impl fmt::Debug for NotifyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotifyHandle").finish_non_exhaustive()
    }
}
