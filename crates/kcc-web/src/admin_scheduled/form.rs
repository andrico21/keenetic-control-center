//! The add and edit dialog: its fields as typed, the messages under them, and the
//! choices read from the router.

pub(super) mod parse;

use std::sync::OnceLock;

use askama::Template;
use kcc_app::schedules::{
    model::{Action, Schedule},
    time::zones,
};
use kcc_i18n::{bundle::MessageKey, keys};

use super::{choices::Choices, text::DAYS};
use crate::page::{Localize as _, Shell};

/// The action kinds in the dialog: the form value and the label.
const KINDS: [(&str, MessageKey); 4] = [
    ("policy_switch", keys::WEB_ADMIN_SCHEDULED_KIND_POLICY),
    ("preset", keys::WEB_ADMIN_SCHEDULED_KIND_PRESET),
    ("backup", keys::WEB_ADMIN_SCHEDULED_SUMMARY_BACKUP),
    ("reboot", keys::WEB_ADMIN_SCHEDULED_SUMMARY_REBOOT),
];

/// The dialog's fields as typed, shown again after a refusal or a refresh.
#[derive(Debug, Clone, Default)]
pub(super) struct Typed {
    /// The edited schedule's id; empty when adding.
    id: String,
    /// Display name.
    name: String,
    /// Router profile id.
    router: String,
    /// Ticked day names, `mon`..`sun`.
    days: Vec<String>,
    /// Hour.
    hour: String,
    /// Minute.
    minute: String,
    /// IANA zone name.
    zone: String,
    /// Action kind: `policy_switch`, `preset`, `backup` or `reboot`.
    kind: String,
    /// The client's MAC.
    mac: String,
    /// Policy name.
    policy: String,
    /// Preset id.
    preset: String,
    /// Whether the documentation-based firmware line is acknowledged.
    ack: bool,
    /// The router name typed to confirm a restart.
    confirm_name: String,
}

impl Typed {
    /// A new schedule's fields: every day at 03:00 in `zone` on `router`, backing up.
    pub(super) fn fresh(zone: &str, router: Option<&str>) -> Self {
        Self {
            router: router.unwrap_or_default().to_owned(),
            days: DAYS.iter().map(|(day, _)| (*day).to_owned()).collect(),
            hour: "3".to_owned(),
            minute: "0".to_owned(),
            zone: zone.to_owned(),
            kind: "backup".to_owned(),
            ..Self::default()
        }
    }

    /// The fields of stored `schedule`, to edit it.
    pub(super) fn of(schedule: &Schedule) -> Self {
        let when = &schedule.when;
        let mut typed = Self {
            id: schedule.id.clone(),
            name: schedule.name.as_str().to_owned(),
            router: schedule.router.clone(),
            days: when.days().names().map(str::to_owned).collect(),
            hour: when.hour().to_string(),
            minute: when.minute().to_string(),
            zone: when.zone().as_str().to_owned(),
            kind: super::text::kind(&schedule.action).to_owned(),
            ..Self::default()
        };
        match &schedule.action {
            Action::PolicySwitch { mac, policy } => {
                mac.as_str().clone_into(&mut typed.mac);
                policy.as_str().clone_into(&mut typed.policy);
            }
            Action::Preset {
                preset_id,
                ack_documentation_tier,
            } => {
                preset_id.as_str().clone_into(&mut typed.preset);
                typed.ack = *ack_documentation_tier;
            }
            Action::Backup | Action::Reboot | _ => {}
        }
        typed
    }

    /// The fields of the submitted `pairs`; unknown fields are ignored.
    pub(super) fn from_pairs(pairs: &[(String, String)]) -> Self {
        let mut typed = Self::default();
        for (field, value) in pairs {
            let slot = match field.as_str() {
                "id" => &mut typed.id,
                "name" => &mut typed.name,
                "router" => &mut typed.router,
                "hour" => &mut typed.hour,
                "minute" => &mut typed.minute,
                "zone" => &mut typed.zone,
                "kind" => &mut typed.kind,
                "mac" => &mut typed.mac,
                "policy" => &mut typed.policy,
                "preset" => &mut typed.preset,
                "confirm_name" => &mut typed.confirm_name,
                "days" => {
                    typed.days.push(value.clone());
                    continue;
                }
                "ack" => {
                    typed.ack = true;
                    continue;
                }
                _ => continue,
            };
            value.clone_into(slot);
        }
        typed
    }

    /// The edited schedule's id; empty when adding.
    pub(super) fn id(&self) -> &str {
        &self.id
    }

    /// Forgets the id: a new schedule's form names none.
    pub(super) fn forget_id(&mut self) {
        self.id.clear();
    }

    /// Display name.
    pub(super) fn name(&self) -> &str {
        &self.name
    }

    /// Router profile id.
    pub(super) fn router(&self) -> &str {
        &self.router
    }

    /// Action kind.
    pub(super) fn kind(&self) -> &str {
        &self.kind
    }

    /// Whether `day` is ticked.
    fn has_day(&self, day: &str) -> bool {
        self.days.iter().any(|ticked| ticked == day)
    }
}

/// The messages under refused fields, and the refusal above them; empty for none.
#[derive(Debug, Clone, Default)]
pub(super) struct Errors {
    /// Above the form: why the scheduler or the store refused.
    general: String,
    /// Under the name.
    name: String,
    /// Under the router.
    router: String,
    /// Under the days.
    days: String,
    /// Under the hour.
    hour: String,
    /// Under the minute.
    minute: String,
    /// Under the zone.
    zone: String,
    /// Under the action.
    kind: String,
    /// Under the client.
    client: String,
    /// Under the policy.
    policy: String,
    /// Under the preset.
    preset: String,
    /// Under the typed router name.
    confirm: String,
}

/// A field a message can be shown under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// The name.
    Name,
    /// The router.
    Router,
    /// The days.
    Days,
    /// The hour.
    Hour,
    /// The minute.
    Minute,
    /// The zone.
    Zone,
    /// The action.
    Kind,
    /// The client.
    Client,
    /// The policy.
    Policy,
    /// The preset.
    Preset,
    /// The typed router name.
    Confirm,
}

impl Errors {
    /// Shows `message` under `field`.
    fn set(&mut self, field: Field, message: String) {
        let slot = match field {
            Field::Name => &mut self.name,
            Field::Router => &mut self.router,
            Field::Days => &mut self.days,
            Field::Hour => &mut self.hour,
            Field::Minute => &mut self.minute,
            Field::Zone => &mut self.zone,
            Field::Kind => &mut self.kind,
            Field::Client => &mut self.client,
            Field::Policy => &mut self.policy,
            Field::Preset => &mut self.preset,
            Field::Confirm => &mut self.confirm,
        };
        *slot = message;
    }

    /// Shows `message` above the form.
    pub(super) fn refuse(&mut self, message: String) {
        self.general = message;
    }

    /// Shows `message` under the name.
    pub(super) fn refuse_name(&mut self, message: String) {
        self.set(Field::Name, message);
    }
}

/// The add or edit dialog.
#[derive(Template)]
#[template(path = "partials/admin_scheduled_editor.html")]
pub(super) struct Editor {
    /// Locale carrier.
    shell: Shell,
    /// The dialog's title.
    title: String,
    /// Where the form posts, and where a changed router or action reloads the dialog.
    urls: (&'static str, &'static str),
    /// The submit button's label.
    submit: MessageKey,
    /// The routers the role sees.
    routers: Vec<String>,
    /// Every zone of the bundled database, suggested for the zone field.
    zones: &'static [String],
    /// The day checkboxes: value and label.
    days: [(&'static str, MessageKey); 7],
    /// The action choices: value and label.
    kinds: [(&'static str, MessageKey); 4],
    /// The fields as typed.
    typed: Typed,
    /// What the router offers.
    choices: Choices,
    /// Field errors.
    errors: Errors,
}

localized!(Editor);

impl Editor {
    /// The dialog titled `title` in `shell`'s locale with `typed` and `choices`, among
    /// `routers`; it adds a schedule unless `typed` names one.
    pub(super) fn new(
        shell: Shell,
        title: String,
        (routers, typed): (Vec<String>, Typed),
        choices: Choices,
    ) -> Self {
        let (urls, submit) = if typed.id.is_empty() {
            (
                ("/ui/admin/scheduled", "/ui/admin/scheduled/new"),
                keys::WEB_ADMIN_SCHEDULED_CREATE,
            )
        } else {
            (
                ("/ui/admin/scheduled/edit", "/ui/admin/scheduled/edit"),
                keys::COMMON_SAVE,
            )
        };
        Self {
            shell,
            title,
            urls,
            submit,
            routers,
            zones: zone_names(),
            days: DAYS,
            kinds: KINDS,
            typed,
            choices,
            errors: Errors::default(),
        }
    }

    /// The submit button's label.
    const fn submit_label(&self) -> MessageKey {
        self.submit
    }

    /// Shows `errors`.
    pub(super) fn refuse_all(&mut self, errors: Errors) {
        self.errors = errors;
    }
}

/// Every zone of the bundled database, read once: the bundled data never changes.
fn zone_names() -> &'static [String] {
    /// The zone names, sorted as the database lists them.
    static NAMES: OnceLock<Vec<String>> = OnceLock::new();
    NAMES.get_or_init(|| zones().available().map(|name| name.to_string()).collect())
}
