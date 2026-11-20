//! Starting, feeding and stopping the notifier.

extern crate alloc;

use alloc::sync::Arc;
use core::{mem, sync::atomic::AtomicBool};
use std::sync::{Mutex, PoisonError, RwLock};

use kcc_app::{notify_store::NotifyEvent, settings::ConfigError};
use kcc_i18n::locale::Locale;
use kcc_telemetry::notify::{
    bot::TelegramClient,
    delivery::{Outbox, OutboxConfig},
    failure::SendError,
};
use tokio::{sync::watch, task::spawn_blocking};

use super::{
    Deps, FLUSH_WAIT, NotifyHandle, Options, Shared, audits, current,
    current::Current,
    failed_jobs::{self, ScheduledJobs},
    lock,
    memory::Firmware,
    render, routers,
};
use crate::{server_error::ServerError, state_watch::Follower};

impl NotifyHandle {
    /// Builds the Bot API client and the outbox, applies the stored settings and starts
    /// following them and the event sources.
    ///
    /// # Errors
    ///
    /// [`ServerError::Config`] when the Bot API client cannot be built from
    /// `[notify.telegram]` (no address, an unreadable or invalid CA file).
    // NOT cancel-safe: dropped after the outbox started, the outbox task runs on without
    // a handle that could stop it.
    pub(crate) async fn start(deps: Deps, options: Options) -> Result<Self, ServerError> {
        let Options {
            telegram,
            default_locale,
            zone,
            timings,
        } = options;
        let api_url = telegram
            .api_url
            .ok_or_else(|| unusable(SendError::NotConfigured))?;
        let client = TelegramClient::new(&api_url, telegram.ca_file.as_deref())
            .await
            .map_err(unusable)?;
        let current = Arc::new(RwLock::new(Current::off(default_locale)));
        let language = Arc::clone(&current);
        let summary = OutboxConfig::new(move |count| {
            let locale = language
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .locale();
            render::dropped(locale, count)
        });
        let outbox = Outbox::spawn(
            client,
            summary,
            deps.state.clone(),
            deps.metrics.clone(),
            timings,
        );
        let state = deps.state.clone();
        let firmware = match spawn_blocking(move || Firmware::load(&state)).await {
            Ok(Ok(loaded)) => loaded,
            Ok(Err(error)) => {
                tracing::warn!(%error, "announced firmware versions cannot be read");
                Firmware::default()
            }
            Err(error) => {
                tracing::warn!(%error, "reading the announced firmware versions did not finish");
                Firmware::default()
            }
        };
        let (reloads, reload_requests) = watch::channel(());
        let shared = Arc::new(Shared {
            outbox,
            current,
            default_locale,
            zone,
            timings,
            deps,
            mutes: Mutex::default(),
            scheduled: ScheduledJobs::default(),
            firmware: Mutex::new(firmware),
            writer_stopped: AtomicBool::new(false),
            reloads: Arc::new(reloads),
            watching: watch::channel(false).0,
            tasks: Mutex::default(),
        });
        drop(current::reload(&shared).await);
        *lock(&shared.tasks) = vec![
            tokio::spawn(follow_settings(Arc::clone(&shared), reload_requests)),
            tokio::spawn(routers::supervise(Arc::clone(&shared))),
            tokio::spawn(audits::follow(Arc::clone(&shared))),
            tokio::spawn(failed_jobs::follow(Arc::clone(&shared))),
        ];
        Ok(Self { shared })
    }

    /// Queues the line `render` writes in the message language when `event` is selected
    /// and notifications are on.
    #[expect(dead_code, reason = "the scheduler reports its runs")]
    pub(crate) fn report<F>(&self, event: NotifyEvent, render: F)
    where
        F: FnOnce(Locale) -> String,
    {
        self.shared.emit(event, render);
    }

    /// Mutes `router`'s offline and online messages until `until` (Unix seconds).
    #[expect(dead_code, reason = "the scheduler mutes the routers it restarts")]
    pub(crate) fn mute(&self, router: &str, until: u64) {
        self.shared.mute(router, until);
    }

    /// The set the scheduler registers its jobs in.
    #[expect(dead_code, reason = "the scheduler registers the jobs it starts")]
    pub(crate) fn scheduled_jobs(&self) -> ScheduledJobs {
        self.shared.scheduled.clone()
    }

    /// Reports once that the audit writer stopped.
    pub(crate) fn writer_stopped(&self) {
        self.shared.writer_stopped();
    }

    /// The state watcher's follower that reloads the settings.
    pub(crate) fn follower(&self) -> Arc<dyn Follower> {
        Arc::new(Reloader(Arc::clone(&self.shared.reloads)))
    }

    /// Stops the event sources, gives the queued lines at most [`FLUSH_WAIT`] and stops
    /// the outbox; what is still queued then is lost and counted in the log.
    // NOT cancel-safe: dropped midway, the outbox may run on with lines queued.
    pub(crate) async fn stop(&self) {
        let tasks = mem::take(&mut *lock(&self.shared.tasks));
        for task in tasks {
            task.abort();
        }
        if !self.shared.outbox.flush(FLUSH_WAIT).await {
            tracing::warn!(
                queued = self.shared.outbox.status().queued,
                "notifications still queued at exit are lost"
            );
        }
        self.shared.outbox.shutdown().await;
    }
}

/// Reloads the settings whenever asked, until the notifier stops.
// cancel-safe: see `current::reload`.
async fn follow_settings(shared: Arc<Shared>, mut requests: watch::Receiver<()>) {
    while requests.changed().await.is_ok() {
        drop(current::reload(&shared).await);
    }
}

/// Tells the notifier to reload when its state files change.
#[derive(Debug)]
struct Reloader(Arc<watch::Sender<()>>);

impl Follower for Reloader {
    fn reload(&self) {
        self.0.send_replace(());
    }
}

/// The configuration error for a Bot API client that cannot be built.
#[expect(
    clippy::match_same_arms,
    reason = "every known class is listed; the wildcard covers classes added later"
)]
fn unusable(error: SendError) -> ServerError {
    let (field, reason) = match error {
        SendError::CaFile => ("notify.telegram.ca_file", "cannot be read"),
        SendError::Certificate => (
            "notify.telegram.ca_file",
            "does not hold a valid PEM certificate",
        ),
        SendError::NotConfigured => ("notify.telegram.api_url", "must be set"),
        SendError::RetryAfter(_)
        | SendError::TokenRejected
        | SendError::ChatUnavailable(_)
        | SendError::Rejected
        | SendError::Transient { status: _ }
        | SendError::AddressRefused
        | SendError::Client
        | SendError::Stopped => ("notify.telegram", "the Bot API client cannot be built"),
        _ => ("notify.telegram", "the Bot API client cannot be built"),
    };
    ServerError::Config(ConfigError::Invalid {
        field: field.to_owned(),
        reason,
    })
}
