//! What the page shows: the status, the settings, the chats, the token and the test
//! message, as one region every change answers with.

mod chats;

use askama::Template;
use kcc_app::notify_store::recipients::Chat;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    format, keys,
    locale::Locale,
};

use super::{
    form::{ChatDraft, EVENTS},
    store::Seen,
};
use crate::{
    admin_shared::Timestamp,
    page::{Localize as _, Shell, Theme},
    page_kit::{context::fragment_shell, outcome::Toast},
    table::view::TableView,
};

/// A field a message can be shown under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Field {
    /// The language.
    Locale,
    /// The events.
    Events,
    /// The token.
    Token,
    /// The chat id.
    ChatId,
    /// The chat label.
    ChatLabel,
    /// The topic id.
    ChatThread,
    /// The test message's chat.
    TestChat,
}

/// The messages under refused fields; empty for none.
#[derive(Debug, Clone, Default)]
pub(super) struct Errors {
    /// Under the language.
    locale: String,
    /// Under the events.
    events: String,
    /// Under the token.
    token: String,
    /// Under the chat id.
    chat_id: String,
    /// Under the chat label.
    chat_label: String,
    /// Under the topic id.
    chat_thread: String,
    /// Under the test message's chat.
    test_chat: String,
}

impl Errors {
    /// Shows `message` under `field`.
    pub(super) fn set(&mut self, field: Field, message: String) {
        let slot = match field {
            Field::Locale => &mut self.locale,
            Field::Events => &mut self.events,
            Field::Token => &mut self.token,
            Field::ChatId => &mut self.chat_id,
            Field::ChatLabel => &mut self.chat_label,
            Field::ChatThread => &mut self.chat_thread,
            Field::TestChat => &mut self.test_chat,
        };
        *slot = message;
    }
}

/// One option of a select: its value, its label and whether it is selected.
pub(super) struct Choice {
    /// Submitted value.
    value: String,
    /// Shown label.
    label: String,
    /// Whether it is selected.
    selected: bool,
}

/// The settings' switches.
pub(super) struct Toggles {
    /// Whether notifications are sent.
    enabled: bool,
    /// Whether clients are named by name and MAC.
    details: bool,
}

/// One event checkbox.
pub(super) struct EventCheck {
    /// Submitted value.
    code: &'static str,
    /// Label.
    label: MessageKey,
    /// Whether it is ticked.
    checked: bool,
}

/// The page's region: every panel, refreshed by each change.
#[derive(Template)]
#[template(path = "partials/admin_notify_region.html")]
pub(super) struct Region {
    /// Locale carrier.
    shell: Shell,
    /// Whether it is sent out of band, as the answer to a change.
    oob: bool,
    /// Outcome toasts of the change.
    toasts: Vec<Toast>,
    /// Whether Telegram refused the bot token.
    rejected: bool,
    /// The running notifier's queued and dropped counts; `None` without a notifier.
    live: Option<(String, String)>,
    /// The Bot API address from `kcc.toml`.
    api_url: String,
    /// Whether a bot token is set.
    token_set: bool,
    /// When the token was set.
    token_saved: Option<Timestamp>,
    /// The settings' switches.
    toggles: Toggles,
    /// The language choices.
    locales: Vec<Choice>,
    /// The event checkboxes.
    events: Vec<EventCheck>,
    /// The chats table.
    chats: TableView,
    /// The chats a test message can go to.
    test_chats: Vec<Choice>,
    /// The add-chat form's fields.
    draft: ChatDraft,
    /// Field errors.
    errors: Errors,
    /// The test message's outcome: notice tone and text.
    test_result: Option<(&'static str, String)>,
}

localized!(Region);
fragment!(Region);

impl Region {
    /// The region of `seen` in `locale`, showing `api_url`, sent out of band.
    pub(super) fn new(locale: Locale, seen: &Seen, api_url: Option<&str>) -> Self {
        let settings = seen.settings();
        let runtime = seen.runtime();
        let status = seen.status();
        let mut locales = vec![Choice {
            value: String::new(),
            label: tr(locale, keys::WEB_ADMIN_NOTIFY_LOCALE_DEFAULT, None),
            selected: settings.locale.is_none(),
        }];
        locales.extend(Locale::ALL.into_iter().map(|language| Choice {
            value: language.tag().to_owned(),
            label: tr(
                locale,
                Shell::new(language, Theme::System).locale_label(),
                None,
            ),
            selected: settings.locale == Some(language),
        }));
        let disabled = |chat: &Chat| {
            status
                .and_then(|live| live.disabled_chats.get(&chat.id).copied())
                .or_else(|| {
                    runtime
                        .disabled_chats
                        .get(&chat.id)
                        .map(|entry| entry.reason)
                })
        };
        Self {
            shell: fragment_shell(locale),
            oob: true,
            toasts: Vec::new(),
            rejected: runtime.token_rejected_at.is_some()
                || status.is_some_and(|live| live.token_rejected),
            live: status.map(|live| {
                (
                    format::integer(locale, u64::try_from(live.queued).unwrap_or(u64::MAX)),
                    format::integer(locale, live.dropped),
                )
            }),
            api_url: api_url.map_or_else(
                || tr(locale, keys::WEB_ADMIN_SERVER_NONE, None),
                str::to_owned,
            ),
            token_set: runtime.token_set_at.is_some(),
            token_saved: runtime
                .token_set_at
                .and_then(|at| Timestamp::at(at, locale)),
            toggles: Toggles {
                enabled: settings.enabled,
                details: settings.include_client_details,
            },
            locales,
            events: EVENTS
                .into_iter()
                .map(|(event, code, label)| EventCheck {
                    code,
                    label,
                    checked: settings.events.contains(&event),
                })
                .collect(),
            chats: chats::table(settings.chats.as_slice(), locale, disabled),
            test_chats: settings
                .chats
                .as_slice()
                .iter()
                .map(|chat| Choice {
                    value: chat.id.as_str().to_owned(),
                    label: chat.label.as_str().to_owned(),
                    selected: false,
                })
                .collect(),
            draft: ChatDraft::default(),
            errors: Errors::default(),
            test_result: None,
        }
    }

    /// The region for the page itself, not sent out of band.
    pub(super) const fn inline(mut self) -> Self {
        self.oob = false;
        self
    }

    /// Adds the change's `toast`.
    pub(super) fn toast(&mut self, toast: Toast) {
        self.toasts.push(toast);
    }

    /// Shows `message` under `field`.
    pub(super) fn refuse(&mut self, field: Field, message: String) {
        self.errors.set(field, message);
    }

    /// Shows every message of `errors`.
    pub(super) fn refuse_all(&mut self, errors: Errors) {
        self.errors = errors;
    }

    /// Fills the add-chat form with `draft`.
    pub(super) fn keep_draft(&mut self, draft: ChatDraft) {
        self.draft = draft;
    }

    /// Shows the test message's outcome `message` in `tone`.
    pub(super) fn show_test(&mut self, tone: &'static str, message: String) {
        self.test_result = Some((tone, message));
    }

    /// Keeps the chat `id` selected in the test message's form.
    pub(super) fn select_test_chat(&mut self, id: &str) {
        for choice in &mut self.test_chats {
            choice.selected = choice.value == id;
        }
    }
}
