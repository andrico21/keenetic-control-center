//! Telegram notification state: the settings an admin edits (`notify.json`), the
//! delivery state only kcc writes (`notify_state.json`) and the sealed bot token
//! (`notify/telegram.token.sealed`, see [`token`]).
//!
//! The Bot API address is not here: it lives in `kcc.toml`
//! ([`crate::settings::notifications::TelegramConfig`]), so whoever can edit this state cannot
//! send the token to another host. No error of this module carries the value it refused.

mod locale_tag;
pub mod recipients;
pub mod token;

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};

use kcc_i18n::locale::Locale;
use serde::{Deserialize, Serialize};

use self::recipients::{ChatId, Chats};
use crate::{
    persist::{Migration, StateDoc, StateError},
    secrets::CryptoError,
};

/// A failure reading, checking or storing notification state. Never carries a value.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NotifyError {
    /// A value was refused; only the field is named.
    #[error("invalid value for {field}")]
    Invalid {
        /// The refused field.
        field: &'static str,
    },
    /// State locking or filesystem persistence failed.
    #[error("notification state storage failed")]
    State(#[source] StateError),
    /// Sealing or opening the bot token failed.
    #[error("bot token encryption failed")]
    Crypto(#[source] CryptoError),
    /// The sealed bot token record has another schema or shape.
    #[error("sealed bot token record is invalid")]
    Record,
}

impl From<StateError> for NotifyError {
    #[inline]
    fn from(source: StateError) -> Self {
        Self::State(source)
    }
}

impl From<CryptoError> for NotifyError {
    #[inline]
    fn from(source: CryptoError) -> Self {
        Self::Crypto(source)
    }
}

/// One kind of event a notification can be sent for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NotifyEvent {
    /// A router went offline or came back.
    RouterDownUp,
    /// A router refused kcc's login.
    RouterLogin,
    /// A change failed.
    ChangeFailed,
    /// A scheduled run failed, was skipped, paused or interrupted.
    ScheduledProblem,
    /// A scheduled run succeeded.
    ScheduledSuccess,
    /// An account was locked after failed logins.
    AccountLocked,
    /// The audit chain was repaired or the audit writer stopped.
    AuditProblem,
    /// New router firmware is available.
    FirmwareUpdate,
    /// A background job failed.
    JobFailed,
    /// A new unregistered device joined a router.
    NewDevice,
}

impl NotifyEvent {
    /// Every event.
    pub const ALL: [Self; 10] = [
        Self::RouterDownUp,
        Self::RouterLogin,
        Self::ChangeFailed,
        Self::ScheduledProblem,
        Self::ScheduledSuccess,
        Self::AccountLocked,
        Self::AuditProblem,
        Self::FirmwareUpdate,
        Self::JobFailed,
        Self::NewDevice,
    ];

    /// Whether the event is on in the default settings: all but [`Self::NewDevice`]
    /// (privacy) and [`Self::ScheduledSuccess`] (noise).
    #[inline]
    #[must_use]
    pub const fn on_by_default(self) -> bool {
        match self {
            Self::RouterDownUp
            | Self::RouterLogin
            | Self::ChangeFailed
            | Self::ScheduledProblem
            | Self::AccountLocked
            | Self::AuditProblem
            | Self::FirmwareUpdate
            | Self::JobFailed => true,
            Self::ScheduledSuccess | Self::NewDevice => false,
        }
    }
}

/// `notify.json`: the notification settings an admin edits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct NotifySettings {
    /// Send notifications at all.
    pub enabled: bool,
    /// Message language; `None` follows `[web] default_locale`.
    #[serde(with = "locale_tag")]
    pub locale: Option<Locale>,
    /// Name clients by name and MAC instead of a pseudonym (never by IP).
    pub include_client_details: bool,
    /// The events that are sent.
    pub events: BTreeSet<NotifyEvent>,
    /// The chats every message goes to.
    pub chats: Chats,
}

impl Default for NotifySettings {
    #[inline]
    fn default() -> Self {
        Self {
            enabled: false,
            locale: None,
            include_client_details: false,
            events: NotifyEvent::ALL
                .into_iter()
                .filter(|event| event.on_by_default())
                .collect(),
            chats: Chats::default(),
        }
    }
}

impl StateDoc for NotifySettings {
    const FILE_NAME: &'static str = "notify.json";
    const SCHEMA: u32 = 1;
    const MIGRATIONS: &'static [Migration] = &[];
}

/// `notify_state.json`: delivery state written only by kcc itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct NotifyRuntime {
    /// When the current bot token was set, in Unix seconds.
    pub token_set_at: Option<u64>,
    /// When Telegram last refused the token, in Unix seconds; cleared by a new token.
    pub token_rejected_at: Option<u64>,
    /// Chats Telegram refused, which get no more messages until edited.
    pub disabled_chats: BTreeMap<ChatId, DisabledChat>,
    /// Per router id, the newest firmware version already notified.
    pub firmware_notified: BTreeMap<String, String>,
}

impl StateDoc for NotifyRuntime {
    const FILE_NAME: &'static str = "notify_state.json";
    const SCHEMA: u32 = 1;
    const MIGRATIONS: &'static [Migration] = &[];
}

/// Why and when a chat was disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct DisabledChat {
    /// What Telegram answered.
    pub reason: DisabledReason,
    /// When, in Unix seconds.
    pub at: u64,
}

impl DisabledChat {
    /// A chat disabled for `reason` at `at` (Unix seconds).
    #[inline]
    #[must_use]
    pub const fn new(reason: DisabledReason, at: u64) -> Self {
        Self { reason, at }
    }
}

/// What Telegram answered for a disabled chat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DisabledReason {
    /// HTTP 403: the bot was blocked or removed from the chat.
    Forbidden,
    /// The chat does not exist.
    ChatNotFound,
}
