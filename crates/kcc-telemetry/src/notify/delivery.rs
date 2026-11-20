//! The delivery outbox: one task that merges lines per chat, keeps the Bot API rate
//! limits, retries what failed and records refused tokens and chats in
//! `notify_state.json`.
//!
//! Storm control: a line for a chat whose latest message went out longer than the merge
//! window ago is sent at once; later lines within the window are joined (oldest first)
//! and sent when it ends; a message stays within the length limit and extra lines go
//! into the next one; at most one message per second and 20 per minute per chat; at most
//! 256 waiting lines per chat (the oldest dropped); 429 waits `retry_after`; a refused
//! token stops all sending until another token is configured; a refused chat is disabled;
//! other failures back off from 5 s, doubling up to 5 min; a line older than an hour is
//! dropped. After drops, the next delivered message is followed by one summary line. The
//! outbox is locale-agnostic: the summary text comes from [`OutboxConfig`].

mod pacing;
mod persist;
mod task;

use alloc::sync::Arc;
use core::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use kcc_app::{
    notify_store::recipients::{Chat, ChatId},
    persist::StateStore,
};
use secrecy::SecretString;
use tokio::{
    sync::{mpsc, oneshot, watch},
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

use self::task::{Command, Settings, run};
use super::{bot::TelegramClient, failure::SendError};
use crate::metrics::instrumentation::SelfMetrics;

/// Commands waiting for the outbox task; a push beyond it is dropped and counted.
const COMMANDS: usize = 1024;

/// Which chats a line goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChatFilter {
    /// Every configured chat that is not disabled.
    All,
}

/// One notification line.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Line {
    /// The chats it goes to.
    pub chat_filter: ChatFilter,
    /// Plain text.
    pub text: String,
    /// When the event happened; a line older than [`Timings::max_age`] is dropped.
    pub at: Instant,
}

impl Line {
    /// A line for every chat.
    #[inline]
    #[must_use]
    pub const fn new(text: String, at: Instant) -> Self {
        Self {
            chat_filter: ChatFilter::All,
            text,
            at,
        }
    }
}

/// The summary text after `count` dropped lines.
type Summary = Arc<dyn Fn(u64) -> String + Send + Sync>;

/// Outbox settings supplied by the caller.
#[derive(Clone)]
#[non_exhaustive]
pub struct OutboxConfig {
    /// Renders the summary line after drops, in the caller's locale.
    summary: Summary,
}

impl fmt::Debug for OutboxConfig {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboxConfig").finish_non_exhaustive()
    }
}

impl OutboxConfig {
    /// Settings whose summary line after `count` dropped lines is `summary(count)`.
    #[inline]
    #[must_use]
    pub fn new<F>(summary: F) -> Self
    where
        F: Fn(u64) -> String + Send + Sync + 'static,
    {
        Self {
            summary: Arc::new(summary),
        }
    }

    /// The summary line after `count` dropped lines.
    #[inline]
    #[must_use]
    pub fn summary(&self, count: u64) -> String {
        (self.summary)(count)
    }
}

/// The outbox's timing rules; tests shorten them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Timings {
    /// Lines within this long after a send are joined into the next message (30 s).
    pub merge_window: Duration,
    /// Shortest gap between two messages to one chat (1 s).
    pub rate_spacing: Duration,
    /// The window of the per-chat limit of 20 messages (60 s).
    pub rate_window: Duration,
    /// First wait after a transient failure (5 s); it doubles per failure.
    pub backoff_base: Duration,
    /// Longest wait after transient failures (5 min).
    pub backoff_cap: Duration,
    /// Age after which a waiting line is dropped (1 h).
    pub max_age: Duration,
}

impl Default for Timings {
    #[inline]
    fn default() -> Self {
        Self {
            merge_window: Duration::from_secs(30),
            rate_spacing: Duration::from_secs(1),
            rate_window: Duration::from_secs(60),
            backoff_base: Duration::from_secs(5),
            backoff_cap: Duration::from_secs(300),
            max_age: Duration::from_secs(3600),
        }
    }
}

/// What the outbox is doing, for status pages and banners.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OutboxStatus {
    /// Telegram refused the bot token; nothing is sent until another is configured.
    pub token_rejected: bool,
    /// Configured chats Telegram refused.
    pub disabled_chats: Vec<ChatId>,
    /// Lines waiting, over all chats.
    pub queued: usize,
    /// Line copies dropped since the start (full queue, expiry, refused chat or token).
    pub dropped: u64,
    /// A message is being sent.
    pub sending: bool,
}

/// What the outbox task is spawned with.
struct Parts {
    /// Bot API client.
    client: TelegramClient,
    /// Caller settings.
    config: OutboxConfig,
    /// State directory for `notify_state.json`.
    store: StateStore,
    /// Self-metrics.
    metrics: Option<Arc<SelfMetrics>>,
    /// Timing rules.
    timings: Timings,
    /// Where the status is published.
    status: watch::Sender<OutboxStatus>,
}

/// Spawns the outbox task.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct Outbox;

impl Outbox {
    /// Starts the outbox task on the current runtime. It sends nothing until
    /// [`OutboxHandle::configure`] gives it a token and chats.
    #[inline]
    #[must_use]
    pub fn spawn(
        client: TelegramClient,
        config: OutboxConfig,
        store: StateStore,
        metrics: Option<Arc<SelfMetrics>>,
        timings: Timings,
    ) -> OutboxHandle {
        let (commands, receiver) = mpsc::channel(COMMANDS);
        let (status, watcher) = watch::channel(OutboxStatus::default());
        let (settings, settings_watcher) = watch::channel(Settings::default());
        let cancel = CancellationToken::new();
        let parts = Parts {
            client,
            config,
            store,
            metrics: metrics.clone(),
            timings,
            status,
        };
        drop(tokio::spawn(run(
            parts,
            receiver,
            settings_watcher,
            cancel.clone(),
        )));
        OutboxHandle {
            commands,
            settings: Arc::new(settings),
            status: watcher,
            cancel,
            shed: Arc::new(AtomicU64::new(0)),
            metrics,
        }
    }
}

/// Handle to a running outbox; clones share the task.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct OutboxHandle {
    /// Commands to the task.
    commands: mpsc::Sender<Command>,
    /// The latest settings.
    settings: Arc<watch::Sender<Settings>>,
    /// The task's published status; closed when the task ended.
    status: watch::Receiver<OutboxStatus>,
    /// Stops the task.
    cancel: CancellationToken,
    /// Lines dropped because the command queue was full.
    shed: Arc<AtomicU64>,
    /// Counts those drops.
    metrics: Option<Arc<SelfMetrics>>,
}

impl OutboxHandle {
    /// Queues `line` for its chats without waiting. When the outbox is overloaded the
    /// line is dropped and counted.
    #[inline]
    pub fn push(&self, line: Line) {
        if self.commands.try_send(Command::Push(line)).is_err() {
            let _before: u64 = self.shed.fetch_add(1, Ordering::Relaxed);
            if let Some(metrics) = &self.metrics {
                metrics.notify_dropped("queue_full", 1);
            }
        }
    }

    /// Replaces the token, the chats and the on/off switch. Chats no longer listed lose
    /// their queue and their disabled mark; another token ends a token refusal.
    #[inline]
    pub fn configure(&self, token: Option<SecretString>, chats: Vec<Chat>, enabled: bool) {
        drop(
            self.settings
                .send_replace(Settings::new(token, chats, enabled)),
        );
    }

    /// Sends a test message to `chat` at once, without merging, within the chat's rate
    /// limits, and answers the outcome.
    ///
    /// # Errors
    ///
    /// [`SendError::NotConfigured`] without a token, [`SendError::TokenRejected`] or
    /// [`SendError::ChatUnavailable`] when the token or the chat is already refused,
    /// [`SendError::Stopped`] when the outbox has stopped, else the delivery failure.
    // NOT cancel-safe: dropped after the request went out, the outcome is lost while the
    // message may still be delivered.
    #[inline]
    pub async fn send_now(&self, chat: Chat, text: String) -> Result<(), SendError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::SendNow { chat, text, reply })
            .await
            .map_err(|_closed| SendError::Stopped)?;
        answer.await.map_err(|_closed| SendError::Stopped)?
    }

    /// The current status.
    #[inline]
    #[must_use]
    pub fn status(&self) -> OutboxStatus {
        let mut status = self.status.borrow().clone();
        status.dropped = status
            .dropped
            .saturating_add(self.shed.load(Ordering::Relaxed));
        status
    }

    /// A receiver that changes whenever the task publishes a new status.
    #[inline]
    #[must_use]
    pub fn watch_status(&self) -> watch::Receiver<OutboxStatus> {
        self.status.clone()
    }

    /// Sends what is waiting without waiting for merge windows (the rate limits still
    /// apply) and waits up to `limit` until nothing is waiting or being sent; answers
    /// whether that point was reached.
    // cancel-safe: only asks the task to flush and observes its status.
    #[inline]
    pub async fn flush(&self, limit: Duration) -> bool {
        let deadline = Instant::now()
            .checked_add(limit)
            .unwrap_or_else(Instant::now);
        let mut status = self.status.clone();
        let (seen, ack) = oneshot::channel();
        let asked = timeout_at(deadline, async {
            self.commands.send(Command::Flush(seen)).await.is_ok() && ack.await.is_ok()
        })
        .await;
        if !matches!(asked, Ok(true)) {
            return false;
        }
        let idle = timeout(
            deadline.saturating_duration_since(Instant::now()),
            status.wait_for(|current| current.queued == 0 && !current.sending),
        )
        .await;
        matches!(idle, Ok(Ok(_)))
    }

    /// Stops the task, dropping waiting lines and any send in progress, and waits until
    /// it has ended.
    // cancel-safe: the stop is requested before the first await; the rest only observes.
    #[inline]
    pub async fn shutdown(&self) {
        self.cancel.cancel();
        let mut status = self.status.clone();
        while status.changed().await.is_ok() {}
    }
}
