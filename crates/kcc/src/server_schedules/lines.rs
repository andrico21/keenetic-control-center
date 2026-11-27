//! The notification line of a scheduled run, as data and as localized text.
//!
//! Lines name the schedule, its router and, for a policy switch or a preset, the policy or
//! the preset; never a client. Every line of a schedule that changes the configuration (policy switch,
//! preset) says that the change is not saved and a router restart undoes it.

use fluent_bundle::FluentArgs;
use kcc_app::{
    notify_store::NotifyEvent,
    schedules::model::{PauseReason, Schedule},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    format, keys,
    locale::Locale,
};

/// What happened to a schedule.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub(crate) enum LineKind {
    /// A policy switch set `policy`.
    PolicySet {
        /// The policy name.
        policy: String,
    },
    /// A backup was stored.
    BackedUp,
    /// The router restarted and answers again.
    Restarted,
    /// A preset was applied and verified, and stays unsaved.
    PresetApplied {
        /// The preset's id.
        preset: String,
    },
    /// A run failed with error code `code`.
    Failed {
        /// Machine-read error code.
        code: String,
    },
    /// A begun run was not carried out, for `reason`.
    Skipped {
        /// Machine-read reason code.
        reason: String,
    },
    /// `count` slots were too late, the last at `time` (local time of the schedule).
    Missed {
        /// How many.
        count: u32,
        /// When the last one was, in the schedule's zone.
        time: String,
    },
    /// The schedule was paused for `reason`.
    Paused {
        /// Why.
        reason: PauseReason,
    },
    /// A run was found started at the server's start; it is not run again.
    Interrupted,
}

/// One line about one schedule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Line {
    /// What happened.
    kind: LineKind,
    /// The schedule's id.
    id: String,
    /// The schedule's name.
    name: String,
    /// Its router.
    router: String,
    /// Whether the schedule's changes stay unsaved.
    unsaved: bool,
}

impl Line {
    /// A line about `schedule`.
    pub(crate) fn new(schedule: &Schedule, kind: LineKind) -> Self {
        Self {
            kind,
            id: schedule.id.clone(),
            name: schedule.name.as_str().to_owned(),
            router: schedule.router.clone(),
            unsaved: schedule.action.changes_configuration(),
        }
    }

    /// What happened.
    #[cfg(test)]
    pub(crate) const fn kind(&self) -> &LineKind {
        &self.kind
    }

    /// The schedule's id.
    #[cfg(test)]
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// The schedule's router.
    pub(crate) fn router(&self) -> &str {
        &self.router
    }

    /// The event the line belongs to.
    pub(crate) const fn event(&self) -> NotifyEvent {
        match self.kind {
            LineKind::PolicySet { policy: _ }
            | LineKind::BackedUp
            | LineKind::Restarted
            | LineKind::PresetApplied { preset: _ } => NotifyEvent::ScheduledSuccess,
            LineKind::Failed { code: _ }
            | LineKind::Skipped { reason: _ }
            | LineKind::Missed { count: _, time: _ }
            | LineKind::Paused { reason: _ }
            | LineKind::Interrupted => NotifyEvent::ScheduledProblem,
        }
    }

    /// The text in `locale`, naming the router `named`.
    pub(crate) fn render(&self, locale: Locale, named: &str) -> String {
        let mut args = FluentArgs::new();
        args.set("name", self.name.clone());
        args.set("router", named.to_owned());
        let key = match &self.kind {
            LineKind::PolicySet { policy } => {
                args.set("policy", policy.clone());
                keys::NOTIFY_SCHEDULED_DONE_POLICY
            }
            LineKind::BackedUp => keys::NOTIFY_SCHEDULED_DONE_BACKUP,
            LineKind::Restarted => keys::NOTIFY_SCHEDULED_DONE_REBOOT,
            LineKind::PresetApplied { preset } => {
                args.set("preset", preset.clone());
                keys::NOTIFY_SCHEDULED_DONE_PRESET
            }
            LineKind::Failed { code } => {
                args.set("reason", reason(locale, code));
                keys::NOTIFY_SCHEDULED_FAILED
            }
            LineKind::Skipped { reason: code } => {
                args.set("reason", reason(locale, code));
                keys::NOTIFY_SCHEDULED_SKIPPED
            }
            LineKind::Missed { count, time } => {
                args.set("count", format::integer(locale, u64::from(*count)));
                args.set("time", time.clone());
                keys::NOTIFY_SCHEDULED_MISSED
            }
            LineKind::Paused { reason: why } => {
                args.set("reason", reason(locale, pause_code(*why)));
                keys::NOTIFY_SCHEDULED_PAUSED
            }
            LineKind::Interrupted => keys::NOTIFY_SCHEDULED_INTERRUPTED,
        };
        let mut text = tr(locale, key, Some(&args));
        if self.unsaved {
            text.push(' ');
            text.push_str(&tr(locale, keys::NOTIFY_SCHEDULED_UNSAVED, None));
        }
        text
    }
}

/// The machine-read code of a pause reason.
pub(crate) const fn pause_code(reason: PauseReason) -> &'static str {
    match reason {
        PauseReason::OwnerUnavailable => "owner_unavailable",
        PauseReason::Forbidden => "forbidden",
        PauseReason::RouterRemoved => "router_removed",
        PauseReason::Manual => "manual",
        _ => "other",
    }
}

/// The localized explanation of the reason or error code `code`.
pub(crate) fn reason(locale: Locale, code: &str) -> String {
    let known: Option<MessageKey> = match code {
        "router_busy" => Some(keys::NOTIFY_SCHEDULED_REASON_ROUTER_BUSY),
        "client_unknown" => Some(keys::NOTIFY_SCHEDULED_REASON_CLIENT_UNKNOWN),
        "policy_unknown" => Some(keys::NOTIFY_SCHEDULED_REASON_POLICY_UNKNOWN),
        "did_not_come_back" => Some(keys::NOTIFY_SCHEDULED_REASON_DID_NOT_COME_BACK),
        "preset_unavailable" => Some(keys::NOTIFY_SCHEDULED_REASON_PRESET_UNAVAILABLE),
        "owner_unavailable" => Some(keys::NOTIFY_SCHEDULED_REASON_OWNER_UNAVAILABLE),
        "forbidden" => Some(keys::NOTIFY_SCHEDULED_REASON_FORBIDDEN),
        "router_removed" => Some(keys::NOTIFY_SCHEDULED_REASON_ROUTER_REMOVED),
        "firmware" => Some(keys::NOTIFY_SCHEDULED_REASON_FIRMWARE),
        "documentation_tier" => Some(keys::NOTIFY_SCHEDULED_REASON_DOCUMENTATION_TIER),
        "not_ready" => Some(keys::NOTIFY_SCHEDULED_REASON_NOT_READY),
        "management_lines" => Some(keys::NOTIFY_SCHEDULED_REASON_MANAGEMENT_LINES),
        "wireguard_key" => Some(keys::NOTIFY_SCHEDULED_REASON_WIREGUARD_KEY),
        "preset_failed" => Some(keys::NOTIFY_SCHEDULED_REASON_PRESET_FAILED),
        "preset_failed_armed" => Some(keys::NOTIFY_SCHEDULED_REASON_PRESET_FAILED_ARMED),
        "preset_rolled_back" => Some(keys::NOTIFY_SCHEDULED_REASON_PRESET_ROLLED_BACK),
        "preset_restored" => Some(keys::NOTIFY_SCHEDULED_REASON_PRESET_RESTORED),
        "preset_state_unknown" => Some(keys::NOTIFY_SCHEDULED_REASON_PRESET_STATE_UNKNOWN),
        _ => None,
    };
    known.map_or_else(
        || {
            let mut args = FluentArgs::new();
            args.set("reason", code.to_owned());
            tr(locale, keys::NOTIFY_SCHEDULED_REASON_OTHER, Some(&args))
        },
        |key| tr(locale, key, None),
    )
}
