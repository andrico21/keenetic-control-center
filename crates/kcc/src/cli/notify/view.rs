//! What `kcc notify` shows: the settings, whether a token is set, and the chats. Never
//! the token itself.

use kcc_app::{
    notify_store::{DisabledReason, NotifyRuntime, NotifySettings},
    schedules::time::{ZoneName, format_local},
};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};
use serde_json::{Value, json};

use super::event_names;
use crate::cli::{context::Ctx, exit::Outcome, output::Out};

/// Shows the stored state: with `--json` the document, else `done` when given (after an
/// edit) or the whole state.
///
/// # Errors
///
/// Returns state or output failures.
pub(super) fn show(ctx: &Ctx, done: Option<MessageKey>) -> Outcome {
    let settings: NotifySettings = ctx.state().read()?.unwrap_or_default();
    let runtime: NotifyRuntime = ctx.state().read()?.unwrap_or_default();
    let out = ctx.out();
    let human = done.map_or_else(|| human(out, &settings, &runtime), |key| out.tr(key, &[]));
    out.emit(&document(&settings, &runtime), &human)
}

/// The `--json` document.
fn document(settings: &NotifySettings, runtime: &NotifyRuntime) -> Value {
    let chats = settings
        .chats
        .as_slice()
        .iter()
        .map(|chat| {
            let disabled = runtime
                .disabled_chats
                .get(&chat.id)
                .map(|mark| json!({ "reason": mark.reason, "at": mark.at }));
            json!({
                "id": chat.id.as_str(),
                "label": chat.label.as_str(),
                "thread": chat.thread,
                "silent": chat.silent,
                "disabled": disabled,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "enabled": settings.enabled,
        "locale": settings.locale.map(Locale::tag),
        "include_client_details": settings.include_client_details,
        "events": event_names(&settings.events),
        "token": {
            "set": runtime.token_set_at.is_some(),
            "set_at": runtime.token_set_at,
            "rejected_at": runtime.token_rejected_at,
        },
        "chats": chats,
    })
}

/// The localized text of the whole state.
fn human(out: Out, settings: &NotifySettings, runtime: &NotifyRuntime) -> String {
    let switch = |on: bool| {
        out.tr(
            if on {
                keys::CLI_NOTIFY_ON
            } else {
                keys::CLI_NOTIFY_OFF
            },
            &[],
        )
    };
    let locale = settings.locale.map_or_else(
        || out.tr(keys::CLI_NOTIFY_LOCALE_DEFAULT, &[]),
        |locale| locale.tag().to_owned(),
    );
    let names = event_names(&settings.events);
    let events = if names.is_empty() {
        out.tr(keys::CLI_NOTIFY_EVENTS_NONE, &[])
    } else {
        names.join(", ")
    };
    let mut lines = vec![
        out.tr(
            keys::CLI_NOTIFY_ENABLED,
            &[("value", &switch(settings.enabled))],
        ),
        out.tr(keys::CLI_NOTIFY_LOCALE, &[("value", &locale)]),
        out.tr(
            keys::CLI_NOTIFY_CLIENT_DETAILS,
            &[("value", &switch(settings.include_client_details))],
        ),
        out.tr(keys::CLI_NOTIFY_EVENTS, &[("value", &events)]),
        runtime.token_set_at.map_or_else(
            || out.tr(keys::CLI_NOTIFY_TOKEN_NONE, &[]),
            |at| out.tr(keys::CLI_NOTIFY_TOKEN_SET, &[("time", &date(at))]),
        ),
    ];
    if let Some(at) = runtime.token_rejected_at {
        lines.push(out.tr(keys::CLI_NOTIFY_TOKEN_REJECTED, &[("time", &date(at))]));
    }
    if settings.chats.as_slice().is_empty() {
        lines.push(out.tr(keys::CLI_NOTIFY_CHATS_NONE, &[]));
    } else {
        lines.push(out.tr(keys::CLI_NOTIFY_CHATS, &[]));
    }
    for chat in settings.chats.as_slice() {
        let mut words = vec![chat.id.as_str().to_owned(), chat.label.as_str().to_owned()];
        if let Some(thread) = chat.thread {
            let topic = thread.to_string();
            words.push(out.tr(keys::CLI_NOTIFY_CHAT_THREAD, &[("value", &topic)]));
        }
        if chat.silent {
            words.push(out.tr(keys::CLI_NOTIFY_CHAT_SILENT, &[]));
        }
        if let Some(mark) = runtime.disabled_chats.get(&chat.id) {
            let key = match mark.reason {
                DisabledReason::Forbidden => keys::CLI_NOTIFY_CHAT_FORBIDDEN,
                DisabledReason::ChatNotFound | _ => keys::CLI_NOTIFY_CHAT_NOT_FOUND,
            };
            words.push(out.tr(key, &[("time", &date(mark.at))]));
        }
        lines.push(format!("  {}", words.join("  ")));
    }
    lines.join("\n")
}

/// `unix` seconds as a UTC date and time.
fn date(unix: u64) -> String {
    match (i64::try_from(unix), ZoneName::parse("UTC")) {
        (Ok(seconds), Ok(utc)) => format_local(seconds, &utc),
        (Err(_), _) | (_, Err(_)) => unix.to_string(),
    }
}
