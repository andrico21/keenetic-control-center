//! `kcc notify`: Telegram notifications set up without the Web UI.
//!
//! It edits the same state as the Web page (`notify.json`, the sealed token), with the
//! same checks and audit parameters; a running `kcc serve` picks the edits up.

mod chats;
mod send;
mod token;
mod view;

extern crate alloc;

use alloc::collections::BTreeSet;

use kcc_app::{
    accounts::{Clock as _, SystemClock},
    audit::AuditEvent,
    notify_store::{NotifyEvent, NotifySettings},
    permissions::Permission,
};
use kcc_i18n::{keys, locale::Locale};
use serde_json::{Value, json};

use super::{
    args_admin::{NotifyChatCommand, NotifyCommand, Switch},
    context::{Ctx, Services},
    exit::{Exit, Failure, Outcome},
};

/// The audit target of every notification action, as on the Web page.
const TARGET: &str = "telegram";

/// Each event with its name on the command line and in `--json`, in display order.
const EVENTS: [(NotifyEvent, &str); NotifyEvent::ALL.len()] = [
    (NotifyEvent::RouterDownUp, "router_down_up"),
    (NotifyEvent::RouterLogin, "router_login"),
    (NotifyEvent::ChangeFailed, "change_failed"),
    (NotifyEvent::ScheduledProblem, "scheduled_problem"),
    (NotifyEvent::ScheduledSuccess, "scheduled_success"),
    (NotifyEvent::AccountLocked, "account_locked"),
    (NotifyEvent::AuditProblem, "audit_problem"),
    (NotifyEvent::FirmwareUpdate, "firmware_update"),
    (NotifyEvent::JobFailed, "job_failed"),
    (NotifyEvent::NewDevice, "new_device"),
];

/// The word that selects the default events or the server's default language.
const DEFAULT: &str = "default";

/// Runs a `notify` command; every one needs `manage_notifications`.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes local state and appends audit entries.
pub(crate) async fn run(ctx: &Ctx, command: NotifyCommand) -> Outcome {
    ctx.principal().require(Permission::ManageNotifications)?;
    match command {
        NotifyCommand::Show => view::show(ctx, None),
        NotifyCommand::Enable => settings(ctx, |stored| stored.enabled = true).await,
        NotifyCommand::Disable => settings(ctx, |stored| stored.enabled = false).await,
        NotifyCommand::Events { events } => {
            let chosen = parse_events(&events)?;
            settings(ctx, |stored| stored.events = chosen).await
        }
        NotifyCommand::Locale { tag } => {
            let chosen = parse_locale(&tag)?;
            settings(ctx, |stored| stored.locale = chosen).await
        }
        NotifyCommand::ClientDetails { switch } => {
            let on = matches!(switch, Switch::On);
            settings(ctx, |stored| stored.include_client_details = on).await
        }
        NotifyCommand::Token { file, clear } => token::run(ctx, file.as_deref(), clear).await,
        NotifyCommand::Chat(NotifyChatCommand::Add(args)) => chats::add(ctx, args).await,
        NotifyCommand::Chat(NotifyChatCommand::Remove { id }) => chats::remove(ctx, &id).await,
        NotifyCommand::Test { chat } => send::test(ctx, chat.as_deref()).await,
    }
}

/// Applies `edit` to the stored settings, audits the result and shows it.
///
/// # Errors
///
/// Returns state or output failures.
// NOT cancel-safe: the settings may be written without their audit entry.
async fn settings<F>(ctx: &Ctx, edit: F) -> Outcome
where
    F: FnOnce(&mut NotifySettings),
{
    let services = ctx.services().await?;
    let stored = ctx.state().update(|stored: &mut NotifySettings| {
        edit(stored);
        stored.clone()
    })?;
    audit(
        ctx,
        &services,
        ("cli.notify_settings", settings_params(&stored)),
        "success",
    )
    .await;
    view::show(ctx, Some(keys::CLI_NOTIFY_SETTINGS_SAVED))
}

/// The audit parameters of the settings: every value, none of them secret.
fn settings_params(settings: &NotifySettings) -> Value {
    json!({
        "enabled": settings.enabled,
        "locale": settings.locale.map(Locale::tag),
        "include_client_details": settings.include_client_details,
        "events": event_names(&settings.events),
    })
}

/// The names of `events`, in display order.
fn event_names(events: &BTreeSet<NotifyEvent>) -> Vec<&'static str> {
    EVENTS
        .into_iter()
        .filter(|(event, _)| events.contains(event))
        .map(|(_, name)| name)
        .collect()
}

/// The events of a comma-separated list, or the default set for `default`.
///
/// # Errors
///
/// Returns a usage failure naming an unknown event.
fn parse_events(list: &str) -> Outcome<BTreeSet<NotifyEvent>> {
    if list.trim() == DEFAULT {
        return Ok(NotifySettings::default().events);
    }
    list.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| {
            EVENTS
                .into_iter()
                .find(|(_, known)| *known == name)
                .map(|(event, _)| event)
                .ok_or_else(|| {
                    let known = EVENTS.map(|(_, known)| known).join(", ");
                    Failure::message(
                        Exit::Usage,
                        keys::CLI_NOTIFY_EVENT_UNKNOWN,
                        &[("value", name), ("known", &known)],
                    )
                })
        })
        .collect()
}

/// The language of `tag`, or `None` for `default`.
///
/// # Errors
///
/// Returns a usage failure for a language the server does not offer.
fn parse_locale(tag: &str) -> Outcome<Option<Locale>> {
    if tag == DEFAULT {
        return Ok(None);
    }
    Locale::ALL
        .into_iter()
        .find(|locale| locale.tag() == tag)
        .map(Some)
        .ok_or_else(|| {
            Failure::message(
                Exit::Usage,
                keys::CLI_NOTIFY_LOCALE_UNKNOWN,
                &[("value", tag)],
            )
        })
}

/// Appends the audit entry of `action` with `params` on the target `telegram`.
// NOT cancel-safe: the writer may append after cancellation.
async fn audit(ctx: &Ctx, services: &Services, (action, params): (&str, Value), outcome: &str) {
    let event = AuditEvent::new(
        SystemClock::default().unix_seconds(),
        ctx.principal().actor(),
        action.to_owned(),
    )
    .with_target(TARGET.to_owned())
    .with_params(params)
    .with_result(outcome.to_owned(), ctx.request_id());
    ctx.append(services, event).await;
}
