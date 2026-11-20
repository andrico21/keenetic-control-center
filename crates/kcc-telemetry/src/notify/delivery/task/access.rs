//! Who may receive: the configured token, chats and switch, and Telegram's refusals of
//! the token or of single chats.

use alloc::collections::{BTreeMap, BTreeSet};

use kcc_app::notify_store::{
    DisabledReason, NotifyRuntime,
    recipients::{Chat, ChatId},
};
use secrecy::SecretString;

use super::Settings;
use crate::notify::failure::SendError;

/// The settings plus the refusals.
#[derive(Debug, Default)]
pub(super) struct Access {
    /// Current settings.
    settings: Settings,
    /// Whether any settings arrived yet.
    configured: bool,
    /// Telegram refused the token.
    token_rejected: bool,
    /// Refused chats.
    disabled: BTreeMap<ChatId, DisabledReason>,
}

impl Access {
    /// Applies new settings with the stored delivery state: the first settings take the
    /// stored token refusal, later ones end it with another token. Answers the chats
    /// still listed, whose disabled marks are kept.
    pub(super) fn configure(
        &mut self,
        settings: Settings,
        runtime: &NotifyRuntime,
    ) -> BTreeSet<ChatId> {
        self.token_rejected = if self.configured {
            self.token_rejected && !self.token_changed(&settings)
        } else {
            runtime.token_rejected_at.is_some()
        };
        self.configured = true;
        let listed: BTreeSet<ChatId> = settings.chats.iter().map(|chat| chat.id.clone()).collect();
        self.disabled = runtime
            .disabled_chats
            .iter()
            .filter(|(chat, _)| listed.contains(*chat))
            .map(|(chat, mark)| (chat.clone(), mark.reason))
            .collect();
        self.settings = settings;
        listed
    }

    /// Whether `settings` brings a token other than the current one.
    pub(super) fn token_changed(&self, settings: &Settings) -> bool {
        self.settings.other_token(settings)
    }

    /// Whether Telegram refused the token.
    pub(super) const fn token_rejected(&self) -> bool {
        self.token_rejected
    }

    /// Whether lines are taken at all: notifications on and a token set.
    pub(super) const fn accepting(&self) -> bool {
        self.settings.enabled && self.settings.token.is_some()
    }

    /// Whether queued lines may be sent.
    pub(super) const fn sending(&self) -> bool {
        self.accepting() && !self.token_rejected
    }

    /// Whether lines for `chat` are kept: accepting, listed and not refused.
    pub(super) fn receives(&self, chat: &ChatId) -> bool {
        self.accepting()
            && !self.disabled.contains_key(chat)
            && self.settings.chats.iter().any(|listed| listed.id == *chat)
    }

    /// The chats lines go to.
    pub(super) fn chats(&self) -> impl Iterator<Item = &Chat> {
        self.settings
            .chats
            .iter()
            .filter(|chat| !self.disabled.contains_key(&chat.id))
    }

    /// The configured chat `id`.
    pub(super) fn chat(&self, id: &ChatId) -> Option<&Chat> {
        self.settings.chats.iter().find(|chat| chat.id == *id)
    }

    /// The token.
    pub(super) fn token(&self) -> Option<SecretString> {
        self.settings.token.clone()
    }

    /// Why a test message to `chat` cannot be sent, if it cannot.
    pub(super) fn refusal(&self, chat: &ChatId) -> Option<SendError> {
        if self.settings.token.is_none() {
            Some(SendError::NotConfigured)
        } else if self.token_rejected {
            Some(SendError::TokenRejected)
        } else {
            self.disabled
                .get(chat)
                .map(|reason| SendError::ChatUnavailable(*reason))
        }
    }

    /// Records Telegram's refusal of the token.
    pub(super) const fn reject_token(&mut self) {
        self.token_rejected = true;
    }

    /// Records Telegram's refusal of `chat`.
    pub(super) fn disable(&mut self, chat: ChatId, reason: DisabledReason) {
        let _previous: Option<DisabledReason> = self.disabled.insert(chat, reason);
    }

    /// The refused chats.
    pub(super) fn disabled(&self) -> Vec<ChatId> {
        self.disabled.keys().cloned().collect()
    }
}
