//! The page's forms as submitted, and the checks of their fields.

extern crate alloc;

use alloc::collections::BTreeSet;

use kcc_app::notify_store::{
    NotifyEvent, NotifySettings,
    recipients::{Chat, ChatId, ChatLabel},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Value, json};

use super::view::{Errors, Field, Region};
use crate::page_kit::secret::write_only;

/// Each event with its checkbox value and label, in display order.
pub(super) const EVENTS: [(NotifyEvent, &str, MessageKey); NotifyEvent::ALL.len()] = [
    (
        NotifyEvent::RouterDownUp,
        "router_down_up",
        keys::WEB_ADMIN_NOTIFY_EVENT_ROUTER_DOWN_UP,
    ),
    (
        NotifyEvent::RouterLogin,
        "router_login",
        keys::WEB_ADMIN_NOTIFY_EVENT_ROUTER_LOGIN,
    ),
    (
        NotifyEvent::ChangeFailed,
        "change_failed",
        keys::WEB_ADMIN_NOTIFY_EVENT_CHANGE_FAILED,
    ),
    (
        NotifyEvent::ScheduledProblem,
        "scheduled_problem",
        keys::WEB_ADMIN_NOTIFY_EVENT_SCHEDULED_PROBLEM,
    ),
    (
        NotifyEvent::ScheduledSuccess,
        "scheduled_success",
        keys::WEB_ADMIN_NOTIFY_EVENT_SCHEDULED_SUCCESS,
    ),
    (
        NotifyEvent::AccountLocked,
        "account_locked",
        keys::WEB_ADMIN_NOTIFY_EVENT_ACCOUNT_LOCKED,
    ),
    (
        NotifyEvent::AuditProblem,
        "audit_problem",
        keys::WEB_ADMIN_NOTIFY_EVENT_AUDIT_PROBLEM,
    ),
    (
        NotifyEvent::FirmwareUpdate,
        "firmware_update",
        keys::WEB_ADMIN_NOTIFY_EVENT_FIRMWARE_UPDATE,
    ),
    (
        NotifyEvent::JobFailed,
        "job_failed",
        keys::WEB_ADMIN_NOTIFY_EVENT_JOB_FAILED,
    ),
    (
        NotifyEvent::NewDevice,
        "new_device",
        keys::WEB_ADMIN_NOTIFY_EVENT_NEW_DEVICE,
    ),
];

/// The settings form: the switches, the language and the ticked events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SettingsForm {
    /// Send notifications at all.
    enabled: bool,
    /// Message language; `None` follows the server's default.
    locale: Option<Locale>,
    /// Name clients by name and MAC.
    details: bool,
    /// The ticked events.
    events: BTreeSet<NotifyEvent>,
}

impl SettingsForm {
    /// The form of the submitted `pairs`; an unknown language, event or field is refused.
    ///
    /// # Errors
    ///
    /// What was refused.
    pub(super) fn parse(pairs: &[(String, String)]) -> Result<Self, Refused> {
        let mut form = Self {
            enabled: false,
            locale: None,
            details: false,
            events: BTreeSet::new(),
        };
        for (field, value) in pairs {
            match field.as_str() {
                "enabled" => form.enabled = true,
                "client_details" => form.details = true,
                "locale" if value.is_empty() => form.locale = None,
                "locale" => {
                    form.locale = Some(
                        Locale::ALL
                            .into_iter()
                            .find(|locale| locale.tag() == value)
                            .ok_or(Refused::Locale)?,
                    );
                }
                "events" => {
                    let (event, _, _) = EVENTS
                        .into_iter()
                        .find(|(_, code, _)| code == value)
                        .ok_or(Refused::Event)?;
                    let _: bool = form.events.insert(event);
                }
                _ => return Err(Refused::Event),
            }
        }
        Ok(form)
    }

    /// Writes the form into `settings`; the chats stay as they are.
    pub(super) fn apply(&self, settings: &mut NotifySettings) {
        settings.enabled = self.enabled;
        settings.locale = self.locale;
        settings.include_client_details = self.details;
        settings.events.clone_from(&self.events);
    }

    /// The audit parameters: every value of the form, which holds no secret.
    pub(super) fn audit(&self) -> Value {
        let events: Vec<&str> = EVENTS
            .into_iter()
            .filter(|(event, _, _)| self.events.contains(event))
            .map(|(_, code, _)| code)
            .collect();
        json!({
            "enabled": self.enabled,
            "locale": self.locale.map(Locale::tag),
            "include_client_details": self.details,
            "events": events,
        })
    }
}

/// A settings form the page refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refused {
    /// A language the server does not offer.
    Locale,
    /// An event or field the server does not know.
    Event,
}

impl Refused {
    /// Shows the refusal in `region` in `locale`.
    pub(super) fn show(self, region: &mut Region, locale: Locale) {
        match self {
            Self::Locale => region.refuse(
                Field::Locale,
                tr(locale, keys::WEB_ADMIN_NOTIFY_ERROR_LOCALE, None),
            ),
            Self::Event => region.refuse(
                Field::Events,
                tr(locale, keys::WEB_ADMIN_NOTIFY_ERROR_EVENT, None),
            ),
        }
    }
}

/// The token form. No `Debug`: the field holds the typed token until it moves into a
/// `SecretString`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenForm {
    /// The pasted token.
    #[serde(default)]
    token: String,
}

impl TokenForm {
    /// The pasted token, moved into a `SecretString`; `None` when the field was empty.
    pub(super) fn into_token(self) -> Option<SecretString> {
        write_only(self.token)
    }
}

/// The add-chat form's fields as typed, shown again after a refusal.
#[derive(Debug, Clone, Default)]
pub(super) struct ChatDraft {
    /// Chat id.
    id: String,
    /// Label.
    label: String,
    /// Topic id.
    thread: String,
    /// Send without sound.
    silent: bool,
}

impl ChatDraft {
    /// Chat id.
    pub(super) fn id(&self) -> &str {
        &self.id
    }

    /// Label.
    pub(super) fn label(&self) -> &str {
        &self.label
    }

    /// Topic id.
    pub(super) fn thread(&self) -> &str {
        &self.thread
    }

    /// Send without sound.
    pub(super) const fn silent(&self) -> bool {
        self.silent
    }
}

/// The add-chat form.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChatForm {
    /// Chat id or `@username`.
    #[serde(default)]
    id: String,
    /// Label.
    #[serde(default)]
    label: String,
    /// Forum topic id; empty for none.
    #[serde(default)]
    thread: String,
    /// Present when "send without sound" is ticked.
    #[serde(default)]
    silent: Option<String>,
}

impl ChatForm {
    /// The fields as typed, to show again.
    pub(super) fn draft(&self) -> ChatDraft {
        ChatDraft {
            id: self.id.clone(),
            label: self.label.clone(),
            thread: self.thread.clone(),
            silent: self.silent.is_some(),
        }
    }

    /// The chat, or the messages under the refused fields in `locale`.
    ///
    /// # Errors
    ///
    /// The field errors when any field is refused.
    pub(super) fn chat(&self, locale: Locale) -> Result<Chat, Box<Errors>> {
        let mut errors = Errors::default();
        let mut refuse = |field, key| errors.set(field, tr(locale, key, None));
        let parsed_id = ChatId::parse(self.id.trim())
            .map_err(|_refused| refuse(Field::ChatId, keys::WEB_ADMIN_NOTIFY_ERROR_CHAT_ID));
        let parsed_label = ChatLabel::parse(self.label.trim())
            .map_err(|_refused| refuse(Field::ChatLabel, keys::WEB_ADMIN_NOTIFY_ERROR_CHAT_LABEL));
        let parsed_thread = match self.thread.trim() {
            "" => Ok(None),
            typed => typed.parse::<i64>().map(Some).map_err(|_refused| {
                refuse(Field::ChatThread, keys::WEB_ADMIN_NOTIFY_ERROR_CHAT_THREAD);
            }),
        };
        let (Ok(id), Ok(label), Ok(thread)) = (parsed_id, parsed_label, parsed_thread) else {
            return Err(Box::new(errors));
        };
        let mut chat = Chat::new(id, label);
        chat.thread = thread;
        chat.silent = self.silent.is_some();
        Ok(chat)
    }
}

/// The remove-chat form.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoveForm {
    /// The stored chat id.
    id: String,
}

impl RemoveForm {
    /// The stored chat id.
    pub(super) fn id(&self) -> &str {
        &self.id
    }
}

/// The test-message form.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TestForm {
    /// The stored chat id.
    #[serde(default)]
    chat: String,
}

impl TestForm {
    /// The stored chat id.
    pub(super) fn chat(&self) -> &str {
        &self.chat
    }
}
