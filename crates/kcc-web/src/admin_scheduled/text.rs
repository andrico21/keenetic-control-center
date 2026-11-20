//! The page's words for a schedule: its action, days, time, state, last run and the
//! scheduler's refusals.

use fluent_bundle::FluentArgs;
use kcc_app::schedules::{
    ledger::{RunRecord, RunState},
    model::{Action, PauseReason, Schedule, ScheduleState},
    time::format_local,
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::ScheduleRefusal;

/// Each day of a schedule with its name in the page, Monday first.
pub(super) const DAYS: [(&str, MessageKey); 7] = [
    ("mon", keys::WEB_SYSTEM_SCHEDULES_MONDAY),
    ("tue", keys::WEB_SYSTEM_SCHEDULES_TUESDAY),
    ("wed", keys::WEB_SYSTEM_SCHEDULES_WEDNESDAY),
    ("thu", keys::WEB_SYSTEM_SCHEDULES_THURSDAY),
    ("fri", keys::WEB_SYSTEM_SCHEDULES_FRIDAY),
    ("sat", keys::WEB_SYSTEM_SCHEDULES_SATURDAY),
    ("sun", keys::WEB_SYSTEM_SCHEDULES_SUNDAY),
];

/// The audit form of `action`'s kind, also the form's value for it.
pub(super) const fn kind(action: &Action) -> &'static str {
    match action {
        Action::PolicySwitch { mac: _, policy: _ } => "policy_switch",
        Action::Preset {
            preset_id: _,
            ack_documentation_tier: _,
        } => "preset",
        Action::Reboot => "reboot",
        Action::Backup | _ => "backup",
    }
}

/// What `action` does, as the table shows it: never the client.
pub(super) fn summary(action: &Action, locale: Locale) -> String {
    let mut args = FluentArgs::new();
    let key = match action {
        Action::PolicySwitch { mac: _, policy } => {
            args.set("policy", policy.as_str().to_owned());
            keys::WEB_ADMIN_SCHEDULED_SUMMARY_POLICY
        }
        Action::Preset {
            preset_id,
            ack_documentation_tier: _,
        } => {
            args.set("preset", preset_id.as_str().to_owned());
            keys::WEB_ADMIN_SCHEDULED_SUMMARY_PRESET
        }
        Action::Reboot => keys::WEB_ADMIN_SCHEDULED_SUMMARY_REBOOT,
        Action::Backup | _ => keys::WEB_ADMIN_SCHEDULED_SUMMARY_BACKUP,
    };
    tr(locale, key, Some(&args))
}

/// The schedule's days, or "Every day".
pub(super) fn days(schedule: &Schedule, locale: Locale) -> String {
    let names: Vec<&str> = schedule.when.days().names().collect();
    if names.len() == DAYS.len() {
        return tr(locale, keys::WEB_ADMIN_SCHEDULED_EVERY_DAY, None);
    }
    DAYS.iter()
        .filter(|(day, _)| names.contains(day))
        .map(|(_, key)| tr(locale, *key, None))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The schedule's time of day and zone, `HH:MM Zone`.
pub(super) fn time(schedule: &Schedule) -> String {
    let when = &schedule.when;
    format!(
        "{:02}:{:02} {}",
        when.hour(),
        when.minute(),
        when.zone().as_str()
    )
}

/// The schedule's state: its tone and words; a paused one says why.
pub(super) const fn state(schedule: &Schedule) -> (&'static str, MessageKey) {
    match schedule.state {
        ScheduleState::Paused { reason, at: _ } => (
            "warning",
            match reason {
                PauseReason::OwnerUnavailable => keys::WEB_ADMIN_SCHEDULED_PAUSED_OWNER,
                PauseReason::Forbidden => keys::WEB_ADMIN_SCHEDULED_PAUSED_FORBIDDEN,
                PauseReason::RouterRemoved => keys::WEB_ADMIN_SCHEDULED_PAUSED_ROUTER,
                PauseReason::Manual | _ => keys::WEB_ADMIN_SCHEDULED_PAUSED,
            },
        ),
        ScheduleState::Active | _ => ("success", keys::WEB_ADMIN_SCHEDULED_ACTIVE),
    }
}

/// The last run of `schedule`: its tone, and its words with the time it ended (or
/// started, while it runs) in the schedule's zone.
pub(super) fn last_run(
    run: &RunRecord,
    schedule: &Schedule,
    locale: Locale,
) -> (&'static str, String) {
    let mut args = FluentArgs::new();
    let (tone, key) = match &run.state {
        RunState::Started => ("info", keys::WEB_ADMIN_SCHEDULED_RUN_STARTED),
        RunState::Succeeded {
            unsaved: true,
            checksum: _,
        } => ("success", keys::WEB_ADMIN_SCHEDULED_RUN_UNSAVED),
        RunState::Succeeded {
            unsaved: false,
            checksum: _,
        } => ("success", keys::WEB_ADMIN_SCHEDULED_RUN_SUCCEEDED),
        RunState::Failed { code } => {
            args.set("reason", code.clone());
            ("error", keys::WEB_ADMIN_SCHEDULED_RUN_FAILED)
        }
        RunState::Skipped { reason } => {
            args.set("reason", reason.clone());
            ("warning", keys::WEB_ADMIN_SCHEDULED_RUN_SKIPPED)
        }
        RunState::Interrupted | _ => ("error", keys::WEB_ADMIN_SCHEDULED_RUN_INTERRUPTED),
    };
    let at = format_local(
        run.finished_at.unwrap_or(run.started_at),
        schedule.when.zone(),
    );
    (tone, format!("{} ({at})", tr(locale, key, Some(&args))))
}

/// The message the page shows for `refusal`.
pub(super) const fn refusal(refusal: ScheduleRefusal) -> MessageKey {
    match refusal {
        ScheduleRefusal::Forbidden => keys::WEB_SCHEDULED_REFUSED_FORBIDDEN,
        ScheduleRefusal::Router => keys::WEB_SCHEDULED_REFUSED_ROUTER,
        ScheduleRefusal::ClientUnknown => keys::WEB_SCHEDULED_REFUSED_CLIENT_UNKNOWN,
        ScheduleRefusal::PolicyUnknown => keys::WEB_SCHEDULED_REFUSED_POLICY_UNKNOWN,
        ScheduleRefusal::PresetUnavailable => keys::WEB_SCHEDULED_REFUSED_PRESET_UNAVAILABLE,
        ScheduleRefusal::Firmware => keys::WEB_SCHEDULED_REFUSED_FIRMWARE,
        ScheduleRefusal::DocumentationTier => keys::WEB_SCHEDULED_REFUSED_DOCUMENTATION_TIER,
        ScheduleRefusal::NotReady => keys::WEB_SCHEDULED_REFUSED_NOT_READY,
        ScheduleRefusal::ManagementLines => keys::WEB_SCHEDULED_REFUSED_MANAGEMENT_LINES,
        ScheduleRefusal::WireguardKey => keys::WEB_SCHEDULED_REFUSED_WIREGUARD_KEY,
        ScheduleRefusal::Busy => keys::WEB_SCHEDULED_REFUSED_BUSY,
        ScheduleRefusal::Unavailable => keys::WEB_SCHEDULED_REFUSED_UNAVAILABLE,
    }
}
