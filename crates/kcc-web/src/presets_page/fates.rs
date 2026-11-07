//! What happens to each setting of a run's plan on the router, and why, in words.

use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_migrate::{
    presets::plan::{PresetInput, PresetPlanItem},
    rules::Disposition,
};

use super::record::Record;

/// What happens to a setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fate {
    /// kcc sends it.
    Send,
    /// The router already has it.
    Present,
    /// Mirror removes the router's own setting.
    Remove,
    /// It waits for a password.
    Input,
    /// Its value differs from the router's.
    Conflict,
    /// The router's firmware cannot take it.
    Unsupported,
    /// The user left it out.
    Excluded,
}

impl Fate {
    /// Every fate, in filter order.
    pub(super) const ALL: [Self; 7] = [
        Self::Send,
        Self::Present,
        Self::Remove,
        Self::Input,
        Self::Conflict,
        Self::Unsupported,
        Self::Excluded,
    ];

    /// The fate of `item`, given whether the user left it out.
    pub(super) fn of(item: &PresetPlanItem, excluded: bool) -> Self {
        if excluded {
            return Self::Excluded;
        }
        match item.disposition {
            Disposition::NeedsInput => Self::Input,
            Disposition::Conflict => Self::Conflict,
            Disposition::Copy | Disposition::Remap => match item.reason.as_str() {
                "preset-already-present" => Self::Present,
                "preset-mirror-remove" => Self::Remove,
                _ => Self::Send,
            },
            Disposition::Unsupported
            | Disposition::SkipHardware
            | Disposition::SkipIdentity
            | _ => Self::Unsupported,
        }
    }

    /// The fate's name in filter links.
    pub(super) const fn slug(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Present => "present",
            Self::Remove => "remove",
            Self::Input => "input",
            Self::Conflict => "conflict",
            Self::Unsupported => "unsupported",
            Self::Excluded => "excluded",
        }
    }

    /// The pill's tone, the migration review's fate names.
    pub(super) const fn tone(self) -> &'static str {
        match self {
            Self::Send => "migrated",
            Self::Remove | Self::Conflict => "conflict",
            Self::Input => "input",
            Self::Present | Self::Unsupported | Self::Excluded => "skipped",
        }
    }

    /// The fate's label.
    pub(super) const fn label(self) -> MessageKey {
        match self {
            Self::Send => keys::WEB_PRESETS_FATE_SEND,
            Self::Present => keys::WEB_PRESETS_FATE_PRESENT,
            Self::Remove => keys::WEB_PRESETS_FATE_REMOVE,
            Self::Input => keys::WEB_MIGRATE_FATE_INPUT,
            Self::Conflict => keys::WEB_MIGRATE_FATE_CONFLICT,
            Self::Unsupported => keys::WEB_MIGRATE_FATE_UNSUPPORTED,
            Self::Excluded => keys::WEB_MIGRATE_FATE_EXCLUDED,
        }
    }

    /// Whether the user may leave the setting in or out.
    pub(super) const fn choosable(self) -> bool {
        !matches!(self, Self::Present | Self::Unsupported)
    }
}

/// Why `item`, which `record` keeps, still blocks the plan, in `locale`.
pub(super) fn blocking(item: &PresetPlanItem, record: &Record, locale: Locale) -> String {
    reason(item, Fate::of(item, false), record, locale)
}

/// Why `item` has `fate` under `record`'s choices, in `locale`.
pub(super) fn reason(item: &PresetPlanItem, fate: Fate, record: &Record, locale: Locale) -> String {
    let mut args = FluentArgs::new();
    let wireguard = item
        .expose_result()
        .is_some_and(|line| line.split_whitespace().nth(3) == Some("private-key"));
    let key = match fate {
        Fate::Excluded => keys::WEB_PRESETS_REASON_EXCLUDED,
        Fate::Input => match &item.needed_input {
            Some(PresetInput::RouterUserPassword { user }) => {
                args.set("name", user.clone());
                keys::WEB_PRESETS_REASON_PASSWORD
            }
            Some(PresetInput::Mapping { source }) => {
                args.set("name", source.clone());
                keys::WEB_PRESETS_REASON_MAPPING
            }
            Some(_) | None => keys::MIGRATE_REASON_NEEDS_INPUT,
        },
        Fate::Conflict => keys::WEB_PRESETS_REASON_CONFLICT,
        Fate::Unsupported => keys::WEB_PRESETS_REASON_UNSUPPORTED,
        Fate::Present => keys::WEB_PRESETS_REASON_PRESENT,
        Fate::Remove => keys::WEB_PRESETS_REASON_MIRROR,
        Fate::Send if wireguard && record.keep_keys() => keys::WEB_PRESETS_REASON_WIREGUARD_KEPT,
        Fate::Send if wireguard => keys::WEB_PRESETS_REASON_WIREGUARD_NEW,
        Fate::Send if item.disposition == Disposition::Remap => keys::WEB_PRESETS_REASON_RENAMED,
        Fate::Send => keys::WEB_PRESETS_REASON_ADD,
    };
    tr(locale, key, Some(&args))
}
