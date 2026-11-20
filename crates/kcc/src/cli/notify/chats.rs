//! `kcc notify chat add|remove`: the chats messages go to. The audit log names a chat by
//! its label only, never by its id.

use kcc_app::{
    notify_store::{
        NotifyRuntime, NotifySettings,
        recipients::{Chat, ChatId, ChatLabel, Chats, MAX_CHATS},
    },
    persist::Edit,
};
use kcc_i18n::keys;
use serde_json::json;

use super::{audit, view};
use crate::cli::{
    args_admin::NotifyChatArgs,
    context::Ctx,
    exit::{Exit, Failure, Outcome},
};

/// Why a chat was not added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unadded {
    /// The id is already listed.
    Exists,
    /// The list holds [`MAX_CHATS`] chats.
    Full,
}

/// Adds the chat of `args` at the end of the list.
///
/// # Errors
///
/// Returns a usage failure for a refused id, label, a listed id or a full list, or state
/// failures.
// NOT cancel-safe: the chat may be stored without its audit entry.
pub(super) async fn add(ctx: &Ctx, args: NotifyChatArgs) -> Outcome {
    let chat_id = parse_id(&args.id)?;
    let label = ChatLabel::parse(args.label.trim()).map_err(|_refused| {
        Failure::message(Exit::Usage, keys::CLI_NOTIFY_CHAT_LABEL_INVALID, &[])
    })?;
    let mut chat = Chat::new(chat_id, label);
    chat.thread = args.thread;
    chat.silent = args.silent;
    let name = chat.label.as_str().to_owned();
    let shown_id = chat.id.as_str().to_owned();
    let services = ctx.services().await?;
    let added = ctx
        .state()
        .update_if_changed(|settings: &mut NotifySettings| {
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
        })?;
    match added {
        Ok(()) => {}
        Err(Unadded::Exists) => {
            return Err(Failure::message(
                Exit::Usage,
                keys::CLI_NOTIFY_CHAT_EXISTS,
                &[("id", &shown_id)],
            ));
        }
        Err(Unadded::Full) => {
            return Err(Failure::message(
                Exit::Usage,
                keys::CLI_NOTIFY_CHATS_FULL,
                &[("max", &MAX_CHATS.to_string())],
            ));
        }
    }
    let params = json!({ "label": name });
    audit(ctx, &services, ("cli.notify_chat_add", params), "success").await;
    view::show(ctx, Some(keys::CLI_NOTIFY_CHAT_ADDED))
}

/// Removes the chat `id` and forgets that Telegram disabled it.
///
/// # Errors
///
/// Returns a usage failure for a refused or unlisted id, or state failures.
// NOT cancel-safe: the removal may be stored without its audit entry.
pub(super) async fn remove(ctx: &Ctx, id: &str) -> Outcome {
    let chat_id = parse_id(id)?;
    let services = ctx.services().await?;
    let removed = ctx
        .state()
        .update_if_changed(|settings: &mut NotifySettings| {
            let mut chats = settings.chats.as_slice().to_vec();
            let Some(at) = chats.iter().position(|chat| chat.id == chat_id) else {
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
    let Some(label) = removed else {
        return Err(Failure::message(
            Exit::Usage,
            keys::CLI_NOTIFY_CHAT_UNKNOWN,
            &[("id", chat_id.as_str())],
        ));
    };
    ctx.state()
        .update_if_changed(|runtime: &mut NotifyRuntime| {
            runtime
                .disabled_chats
                .remove(&chat_id)
                .map_or(Edit::Unchanged(()), |_mark| Edit::Changed(()))
        })?;
    let params = json!({ "label": label });
    audit(
        ctx,
        &services,
        ("cli.notify_chat_remove", params),
        "success",
    )
    .await;
    view::show(ctx, Some(keys::CLI_NOTIFY_CHAT_REMOVED))
}

/// The chat id `text`.
///
/// # Errors
///
/// Returns a usage failure for a refused id.
pub(super) fn parse_id(text: &str) -> Outcome<ChatId> {
    ChatId::parse(text.trim())
        .map_err(|_refused| Failure::message(Exit::Usage, keys::CLI_NOTIFY_CHAT_ID_INVALID, &[]))
}
