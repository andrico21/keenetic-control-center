//! `kcc notify test`: one test message from this process.
//!
//! It goes straight through the Bot API client with the `[notify.telegram]` settings of
//! `kcc.toml`. No outbox: one message has nothing to merge or pace, and the client
//! already cuts it to the Bot API limit.

use kcc_app::{
    accounts::{Clock as _, SystemClock},
    notify_store::{
        DisabledChat, NotifyRuntime, NotifySettings,
        recipients::{Chat, ChatId},
        token::NotifySecrets,
    },
    persist::StateStore,
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_telemetry::notify::{
    bot::{Outgoing, TelegramClient},
    failure::SendError,
};
use kcc_web::admin_notify::NotifyTestError;
use secrecy::SecretString;
use serde_json::json;

use super::{audit, chats::parse_id, token::stored};
use crate::cli::{
    context::Ctx,
    exit::{Exit, Failure, Outcome},
};

/// Sends a test message to the chat `chosen`, else the first listed chat; a failure exits
/// with the router code and names its class.
///
/// # Errors
///
/// Returns a usage failure without a listed chat, the router failure naming the class, or
/// key, state or output failures.
// NOT cancel-safe: dropped after the request went out, the message may be delivered
// without an audit entry.
pub(super) async fn test(ctx: &Ctx, chosen: Option<&str>) -> Outcome {
    let settings: NotifySettings = ctx.state().read()?.unwrap_or_default();
    let chat = pick(&settings, chosen)?;
    let services = ctx.services().await?;
    let token =
        NotifySecrets::token(ctx.state(), services.key()).map_err(|error| stored(&error))?;
    let locale = settings
        .locale
        .or_else(|| Locale::from_tag(&ctx.config().web.default_locale))
        .unwrap_or(Locale::En);
    let text = tr(locale, keys::CLI_NOTIFY_TEST_TEXT, None);
    let sent = match token {
        None => Err(NotifyTestError::NoToken),
        Some(secret) => match refusal(ctx.state(), &chat.id)? {
            Some(class) => Err(class),
            None => match send(ctx, &secret, &Outgoing::new(&chat, &text)).await {
                Ok(()) => Ok(()),
                Err(error) => Err(remember(ctx.state(), &chat.id, error)?),
            },
        },
    };
    let label = chat.label.as_str().to_owned();
    let out = ctx.out();
    match sent {
        Ok(()) => {
            let params = json!({ "label": label });
            audit(ctx, &services, ("cli.notify_test", params), "success").await;
            out.emit(
                &json!({ "sent": true, "chat": chat.id.as_str() }),
                &out.tr(keys::CLI_NOTIFY_TEST_SENT, &[("name", &label)]),
            )
        }
        Err(class) => {
            let params = json!({ "label": label, "failure": class.code() });
            audit(ctx, &services, ("cli.notify_test", params), "failed").await;
            Err(Failure::message(
                Exit::Router,
                keys::CLI_NOTIFY_TEST_FAILED,
                &[
                    ("reason", &out.tr(reason(class), &[])),
                    ("class", class.code()),
                ],
            )
            .headlined(keys::CLI_NOTIFY_TEST_NOT_SENT))
        }
    }
}

/// The chat `chosen`, else the first listed one.
///
/// # Errors
///
/// Returns a usage failure for an unlisted chat or an empty list.
fn pick(settings: &NotifySettings, chosen: Option<&str>) -> Outcome<Chat> {
    let chats = settings.chats.as_slice();
    let Some(text) = chosen else {
        return chats
            .first()
            .cloned()
            .ok_or_else(|| Failure::message(Exit::Usage, keys::CLI_NOTIFY_NO_CHATS, &[]));
    };
    let id = parse_id(text)?;
    chats
        .iter()
        .find(|chat| chat.id == id)
        .cloned()
        .ok_or_else(|| {
            Failure::message(
                Exit::Usage,
                keys::CLI_NOTIFY_CHAT_UNKNOWN,
                &[("id", id.as_str())],
            )
        })
}

/// Why no request is made, as the running notifier decides: a refused token or a
/// disabled chat stays refused until the token is replaced or the chat re-added.
///
/// # Errors
///
/// Returns state failures.
fn refusal(state: &StateStore, chat: &ChatId) -> Outcome<Option<NotifyTestError>> {
    let runtime: NotifyRuntime = state.read()?.unwrap_or_default();
    Ok(if runtime.token_rejected_at.is_some() {
        Some(NotifyTestError::TokenRejected)
    } else if runtime.disabled_chats.contains_key(chat) {
        Some(NotifyTestError::ChatRefused)
    } else {
        None
    })
}

/// Sends `message` with `secret` through a client built from `[notify.telegram]`.
///
/// # Errors
///
/// Returns why the message was not delivered.
// NOT cancel-safe: dropped after the request went out, the message may be delivered
// without the caller learning it.
async fn send(ctx: &Ctx, secret: &SecretString, message: &Outgoing) -> Result<(), SendError> {
    let telegram = &ctx.config().notify.telegram;
    let url = telegram.api_url.as_ref().ok_or(SendError::NotConfigured)?;
    TelegramClient::new(url, telegram.ca_file.as_deref())
        .await?
        .send(secret, message)
        .await
        .map(drop)
}

/// Records a refused token or chat as the running notifier does, and returns the class
/// of `error`.
///
/// # Errors
///
/// Returns state failures.
fn remember(state: &StateStore, chat: &ChatId, error: SendError) -> Outcome<NotifyTestError> {
    let now = SystemClock::default().unix_seconds();
    let recorded = match error {
        SendError::TokenRejected => {
            state.update(|runtime: &mut NotifyRuntime| runtime.token_rejected_at = Some(now))
        }
        SendError::ChatUnavailable(reason) => state.update(|runtime: &mut NotifyRuntime| {
            let _replaced: Option<DisabledChat> = runtime
                .disabled_chats
                .insert(chat.clone(), DisabledChat::new(reason, now));
        }),
        SendError::RetryAfter(_)
        | SendError::Rejected
        | SendError::Transient { status: _ }
        | SendError::AddressRefused
        | SendError::CaFile
        | SendError::Certificate
        | SendError::Client
        | SendError::NotConfigured
        | SendError::Stopped
        | _ => Ok(()),
    };
    recorded?;
    Ok(class(error))
}

/// The failure class of `error`, as the Web page names it.
const fn class(error: SendError) -> NotifyTestError {
    match error {
        SendError::TokenRejected => NotifyTestError::TokenRejected,
        SendError::ChatUnavailable(_) => NotifyTestError::ChatRefused,
        SendError::RetryAfter(_) => NotifyTestError::RateLimited,
        SendError::Rejected => NotifyTestError::Rejected,
        SendError::NotConfigured => NotifyTestError::NoToken,
        SendError::Transient { status: _ }
        | SendError::AddressRefused
        | SendError::CaFile
        | SendError::Certificate
        | SendError::Client
        | SendError::Stopped
        | _ => NotifyTestError::Unreachable,
    }
}

/// The words for the failure `class`.
const fn reason(class: NotifyTestError) -> MessageKey {
    match class {
        NotifyTestError::NoToken => keys::CLI_NOTIFY_FAILURE_NO_TOKEN,
        NotifyTestError::TokenRejected => keys::CLI_NOTIFY_FAILURE_TOKEN_REJECTED,
        NotifyTestError::ChatRefused => keys::CLI_NOTIFY_FAILURE_CHAT_REFUSED,
        NotifyTestError::RateLimited => keys::CLI_NOTIFY_FAILURE_RATE_LIMITED,
        NotifyTestError::Rejected => keys::CLI_NOTIFY_FAILURE_REJECTED,
        NotifyTestError::Unreachable | _ => keys::CLI_NOTIFY_FAILURE_UNREACHABLE,
    }
}
