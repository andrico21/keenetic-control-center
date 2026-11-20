//! `POST /ui/admin/notifications/chats` and `.../chats/remove`: the chats messages go to.
//! The audit log names a chat by its label only, never by its id.

use axum::{Form, extract::State, response::Response};
use kcc_app::{
    notify_store::{
        NotifyRuntime, NotifySettings,
        recipients::{Chat, ChatId, Chats, MAX_CHATS},
    },
    persist::{Edit, StateError, StateStore},
};
use kcc_i18n::{bundle::tr, keys};
use serde_json::json;

use super::{
    form::{ChatForm, RemoveForm},
    page::{changed, missing, refused},
    store::{blocking, store},
    view::Field,
};
use crate::{
    WebState, admin_shared::unavailable, authz::CurrentUser, errors,
    page_kit::context::fragment_shell,
};

/// Why a chat was not added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unadded {
    /// The id is already listed.
    Exists,
    /// The list holds [`MAX_CHATS`] chats.
    Full,
}

/// `POST /ui/admin/notifications/chats`: adds a chat at the end of the list.
// NOT cancel-safe: the chat is written on a blocking thread that finishes even if the future is
// dropped, leaving the change unaudited and the notifier not reloaded.
pub(crate) async fn add_chat(
    State(state): State<WebState>,
    user: CurrentUser,
    Form(form): Form<ChatForm>,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let locale = user.locale();
    let draft = form.draft();
    let chat = match form.chat(locale) {
        Ok(chat) => chat,
        Err(errors) => {
            return refused(&state, locale, |region| {
                region.refuse_all(*errors);
                region.keep_draft(draft);
            })
            .await;
        }
    };
    let label = chat.label.as_str().to_owned();
    let stored = match store(&state) {
        Ok(stored) => stored,
        Err(error) => return errors::internal(&*error, fragment_shell(locale)),
    };
    match blocking(move || append(&stored, chat)).await {
        Ok(Ok(())) => {}
        Ok(Err(unadded)) => {
            let message = tr(
                locale,
                match unadded {
                    Unadded::Exists => keys::WEB_ADMIN_NOTIFY_ERROR_CHAT_EXISTS,
                    Unadded::Full => keys::WEB_ADMIN_NOTIFY_ERROR_CHATS_FULL,
                },
                None,
            );
            return refused(&state, locale, |region| {
                region.refuse(Field::ChatId, message);
                region.keep_draft(draft);
            })
            .await;
        }
        Err(error) => return errors::internal(&*error, fragment_shell(locale)),
    }
    changed(
        &state,
        &user,
        ("web.notify_chat_add", json!({ "label": label })),
        keys::WEB_ADMIN_NOTIFY_CHAT_ADDED,
    )
    .await
}

/// `POST /ui/admin/notifications/chats/remove`: removes the chat `id` and forgets that
/// Telegram disabled it.
// NOT cancel-safe: the removal is written on a blocking thread that finishes even if the future is
// dropped, leaving the change unaudited and the notifier not reloaded.
pub(crate) async fn remove_chat(
    State(state): State<WebState>,
    user: CurrentUser,
    Form(form): Form<RemoveForm>,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let locale = user.locale();
    let Ok(id) = ChatId::parse(form.id()) else {
        return missing();
    };
    let stored = match store(&state) {
        Ok(stored) => stored,
        Err(error) => return errors::internal(&*error, fragment_shell(locale)),
    };
    let label = match blocking(move || remove(&stored, &id)).await {
        Ok(Some(label)) => label,
        Ok(None) => return missing(),
        Err(error) => return errors::internal(&*error, fragment_shell(locale)),
    };
    changed(
        &state,
        &user,
        ("web.notify_chat_remove", json!({ "label": label })),
        keys::WEB_ADMIN_NOTIFY_CHAT_REMOVED,
    )
    .await
}

/// Appends `chat` to the stored chats unless its id is listed or the list is full.
///
/// # Errors
///
/// State failures.
fn append(store: &StateStore, chat: Chat) -> Result<Result<(), Unadded>, StateError> {
    store.update_if_changed(|settings: &mut NotifySettings| {
        let mut chats = settings.chats.as_slice().to_vec();
        if chats.iter().any(|listed| listed.id == chat.id) {
            return Edit::Unchanged(Err(Unadded::Exists));
        }
        if chats.len() >= MAX_CHATS {
            return Edit::Unchanged(Err(Unadded::Full));
        }
        chats.push(chat);
        match Chats::new(chats) {
            Ok(checked) => {
                settings.chats = checked;
                Edit::Changed(Ok(()))
            }
            Err(_refused) => Edit::Unchanged(Err(Unadded::Full)),
        }
    })
}

/// Removes the chat `id` and its disabled mark; its label, or `None` when not listed.
///
/// # Errors
///
/// State failures.
fn remove(store: &StateStore, id: &ChatId) -> Result<Option<String>, StateError> {
    let removed = store.update_if_changed(|settings: &mut NotifySettings| {
        let mut chats = settings.chats.as_slice().to_vec();
        let Some(at) = chats.iter().position(|chat| chat.id == *id) else {
            return Edit::Unchanged(None);
        };
        let chat = chats.remove(at);
        match Chats::new(chats) {
            Ok(rest) => {
                settings.chats = rest;
                Edit::Changed(Some(chat.label.as_str().to_owned()))
            }
            Err(_refused) => Edit::Unchanged(None),
        }
    })?;
    if removed.is_some() {
        store.update_if_changed(|runtime: &mut NotifyRuntime| {
            runtime
                .disabled_chats
                .remove(id)
                .map_or(Edit::Unchanged(()), |_mark| Edit::Changed(()))
        })?;
    }
    Ok(removed)
}
