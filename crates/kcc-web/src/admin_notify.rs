//! Telegram notifications at `/ui/admin/notifications` (`ManageNotifications`).
//!
//! The page edits `notify.json` (whether to send, the message language, the client-detail
//! switch, the events and the chats), seals a pasted bot token and removes it, and sends a
//! test message through the running notifier. The bot token is write-only: it is never
//! rendered, logged or audited, and the page only says when it was set. The Bot API
//! address comes from `kcc.toml` and is shown read-only, so nobody on the Web UI can send
//! the token to another host.
//!
//! `kcc` attaches the running notifier with
//! [`WebState::with_notify`](crate::WebState::with_notify). Without it the page still
//! edits the settings and says they apply at the next start.

extern crate alloc;

pub(crate) mod chats;
mod form;
pub(crate) mod page;
pub(crate) mod settings;
mod store;
pub(crate) mod test_send;
pub(crate) mod token;
mod view;

use alloc::collections::BTreeMap;
use core::{fmt, pin::Pin};

use kcc_app::notify_store::{DisabledReason, recipients::ChatId};

/// The future of one test message: sent, or why not.
pub type TestSend<'send> =
    Pin<Box<dyn Future<Output = Result<(), NotifyTestError>> + Send + 'send>>;

/// The running notifier as the notifications page sees it.
pub trait NotifyControl: fmt::Debug + Send + Sync {
    /// What the notifier reports now; cheap, never waits.
    fn status(&self) -> NotifyStatus;

    /// Sends one test message to the configured chat `chat` (its stored id, such as
    /// `-1001234567890` or `@channel`), outside the queue and the event selection.
    fn send_test<'send>(&'send self, chat: &'send str) -> TestSend<'send>;

    /// Re-reads the notification settings and the bot token after the page changed them.
    /// It must not block: the notifier picks them up on its own task.
    fn reload(&self);
}

/// The running notifier's delivery state, as the page shows it.
///
/// Build it with [`NotifyStatus::new`] and the `with_*` methods; the fields are public for
/// reading.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NotifyStatus {
    /// Messages waiting to be sent.
    pub queued: usize,
    /// Messages dropped since the start: the queue overflowed or a message grew too old.
    pub dropped: u64,
    /// Whether Telegram refused the bot token, which stops all sending.
    pub token_rejected: bool,
    /// Chats Telegram refused, which get no more messages until they are edited.
    pub disabled_chats: BTreeMap<ChatId, DisabledReason>,
}

impl NotifyStatus {
    /// `queued` messages waiting and `dropped` dropped, the token accepted, no chat
    /// disabled.
    #[inline]
    #[must_use]
    pub const fn new(queued: usize, dropped: u64) -> Self {
        Self {
            queued,
            dropped,
            token_rejected: false,
            disabled_chats: BTreeMap::new(),
        }
    }

    /// The same status with Telegram having refused the bot token.
    #[inline]
    #[must_use]
    pub const fn with_token_rejected(mut self) -> Self {
        self.token_rejected = true;
        self
    }

    /// The same status with `chat` disabled for `reason`.
    #[inline]
    #[must_use]
    pub fn with_disabled_chat(mut self, chat: ChatId, reason: DisabledReason) -> Self {
        let _: Option<DisabledReason> = self.disabled_chats.insert(chat, reason);
        self
    }
}

/// Why a test message was not sent: a class only, never the Bot API's own text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NotifyTestError {
    /// No bot token is set.
    #[error("no bot token is set")]
    NoToken,
    /// Telegram refused the bot token (HTTP 401).
    #[error("Telegram refused the bot token")]
    TokenRejected,
    /// Telegram refused the chat: the bot was blocked or removed, or the chat does not
    /// exist.
    #[error("Telegram refused the chat")]
    ChatRefused,
    /// Telegram asked kcc to slow down (HTTP 429).
    #[error("Telegram asked to slow down")]
    RateLimited,
    /// The Bot API could not be reached in time.
    #[error("the Bot API could not be reached")]
    Unreachable,
    /// Telegram answered with another refusal.
    #[error("Telegram did not accept the message")]
    Rejected,
}

impl NotifyTestError {
    /// Stable snake-case code of the class, as the audit log records it.
    #[inline]
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoToken => "no_token",
            Self::TokenRejected => "token_rejected",
            Self::ChatRefused => "chat_refused",
            Self::RateLimited => "rate_limited",
            Self::Unreachable => "unreachable",
            Self::Rejected => "rejected",
        }
    }
}
