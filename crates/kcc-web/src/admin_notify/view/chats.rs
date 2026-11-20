//! The chats table: label, id, topic, sound and state, and each chat's Remove.

use kcc_app::notify_store::{DisabledReason, recipients::Chat};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::table::{
    acts::Act,
    cells::{Cell, Layout},
    head::Head,
    view::TableView,
};

/// Where the remove buttons of the chats table post.
const REMOVE: &str = "/ui/admin/notifications/chats/remove";

/// Each reason Telegram disables a chat for, with the words the page shows.
const REASONS: [(DisabledReason, MessageKey); 2] = [
    (
        DisabledReason::Forbidden,
        keys::WEB_ADMIN_NOTIFY_CHAT_FORBIDDEN,
    ),
    (
        DisabledReason::ChatNotFound,
        keys::WEB_ADMIN_NOTIFY_CHAT_NOT_FOUND,
    ),
];

/// The chats table in `locale`, with each chat's state from `disabled`, or a note when
/// there is none.
pub(super) fn table<F>(chats: &[Chat], locale: Locale, disabled: F) -> TableView
where
    F: Fn(&Chat) -> Option<DisabledReason>,
{
    let mut view = TableView::new("table");
    if chats.is_empty() {
        return view.blank(
            "page__text",
            tr(locale, keys::WEB_ADMIN_NOTIFY_CHATS_EMPTY, None),
        );
    }
    for key in [
        keys::WEB_ADMIN_NOTIFY_CHAT_LABEL,
        keys::WEB_ADMIN_NOTIFY_CHAT_ID,
        keys::WEB_ADMIN_NOTIFY_CHAT_THREAD,
        keys::WEB_ADMIN_NOTIFY_CHAT_SILENT,
        keys::WEB_ADMIN_NOTIFY_CHAT_STATE,
    ] {
        view = view.head(Head::plain(tr(locale, key, None)));
    }
    view = view.head(Head::hidden(tr(locale, keys::WEB_ADMIN_ACTIONS, None)));
    for (index, chat) in chats.iter().enumerate() {
        let id = format!("notify-chat-{}", index.saturating_add(1));
        let state = disabled(chat).map_or(keys::WEB_ADMIN_NOTIFY_CHAT_ACTIVE, |reason| {
            REASONS
                .into_iter()
                .find(|(known, _)| *known == reason)
                .map_or(keys::WEB_ADMIN_NOTIFY_CHAT_DISABLED, |(_, key)| key)
        });
        let remove = Act::post(
            locale,
            keys::WEB_ADMIN_NOTIFY_CHAT_REMOVE,
            (REMOVE.to_owned(), vec![("id", chat.id.as_str().to_owned())]),
        );
        view = view.row(vec![
            Cell::text(chat.label.as_str().to_owned())
                .attr("id", id.clone())
                .head(),
            Cell::code(chat.id.as_str().to_owned()),
            Cell::optional(chat.thread.map(|thread| thread.to_string())),
            Cell::word(
                locale,
                if chat.silent {
                    keys::COMMON_YES
                } else {
                    keys::COMMON_NO
                },
            ),
            Cell::word(locale, state),
            Cell::acts(Layout::Wrapped("admin-actions"), vec![remove.danger()], id),
        ]);
    }
    view
}
