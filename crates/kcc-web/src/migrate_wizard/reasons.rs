//! How the wizard words a classified setting: what happens to it and why.

use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_migrate::rules::{ClassifiedItem, Disposition};

use super::warnings::INSTALL_REASON;

/// The reason of a router-user password hash bound to another realm.
pub(super) const PASSWORD_REASON: &str = "migration-reason-password-realm";

/// The reason of a value that differs from the router's.
const CONFLICT_REASON: &str = "migration-reason-scalar-conflict";

/// What the review says happens to a setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fate {
    /// Migrated as it is, or changed by a map or a typed password.
    Migrated,
    /// Its value differs from the router's; a choice is needed.
    Conflict,
    /// It waits for an input: a password or a component.
    Input,
    /// Left out: it describes the source's hardware or identity.
    Skipped,
    /// The router's firmware has no such command.
    Unsupported,
    /// The user left it out.
    Excluded,
}

impl Fate {
    /// Every fate, in filter order.
    pub(super) const ALL: [Self; 6] = [
        Self::Migrated,
        Self::Conflict,
        Self::Input,
        Self::Skipped,
        Self::Unsupported,
        Self::Excluded,
    ];

    /// The fate named `slug`.
    pub(super) fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|fate| fate.slug() == slug)
    }

    /// The fate of `item`, given whether it conflicts and whether it was left out.
    pub(super) const fn of(item: &ClassifiedItem, conflict: bool, excluded: bool) -> Self {
        if excluded {
            return Self::Excluded;
        }
        if conflict {
            return Self::Conflict;
        }
        match item.disposition {
            Disposition::Copy | Disposition::Remap => Self::Migrated,
            Disposition::Conflict => Self::Conflict,
            Disposition::NeedsInput => Self::Input,
            Disposition::SkipHardware | Disposition::SkipIdentity => Self::Skipped,
            Disposition::Unsupported | _ => Self::Unsupported,
        }
    }

    /// The fate's name in links and data attributes.
    pub(super) const fn slug(self) -> &'static str {
        match self {
            Self::Migrated => "migrated",
            Self::Conflict => "conflict",
            Self::Input => "input",
            Self::Skipped => "skipped",
            Self::Unsupported => "unsupported",
            Self::Excluded => "excluded",
        }
    }

    /// The fate's label.
    pub(super) const fn label(self) -> MessageKey {
        match self {
            Self::Migrated => keys::WEB_MIGRATE_FATE_MIGRATED,
            Self::Conflict => keys::WEB_MIGRATE_FATE_CONFLICT,
            Self::Input => keys::WEB_MIGRATE_FATE_INPUT,
            Self::Skipped => keys::WEB_MIGRATE_FATE_SKIPPED,
            Self::Unsupported => keys::WEB_MIGRATE_FATE_UNSUPPORTED,
            Self::Excluded => keys::WEB_MIGRATE_FATE_EXCLUDED,
        }
    }
}

/// The choice made for a setting whose value differs from the router's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Resolution {
    /// No choice yet.
    Undecided,
    /// The source's value replaces the router's.
    Source,
    /// The router keeps its value.
    Router,
}

/// Why `item` has its fate, in `locale`; `conflict` holds the choice made for a setting
/// whose value differs from the router's.
pub(super) fn reason(
    item: &ClassifiedItem,
    conflict: Option<Resolution>,
    locale: Locale,
) -> String {
    let mut args = FluentArgs::new();
    let key = match (conflict, item.reason_key.as_str()) {
        (Some(Resolution::Source), _) => keys::WEB_MIGRATE_REASON_CONFLICT_SOURCE,
        (Some(Resolution::Router), _) => keys::WEB_MIGRATE_REASON_CONFLICT_ROUTER,
        (Some(Resolution::Undecided), _) | (None, CONFLICT_REASON) => {
            keys::WEB_MIGRATE_REASON_CONFLICT
        }
        (None, PASSWORD_REASON) => {
            args.set("name", word(&item.before, 1));
            if item.disposition == Disposition::NeedsInput {
                keys::WEB_MIGRATE_REASON_PASSWORD
            } else {
                keys::WEB_MIGRATE_REASON_PASSWORD_SET
            }
        }
        (None, INSTALL_REASON) => {
            let component = item
                .needed_input
                .as_deref()
                .and_then(|needed| needed.strip_prefix("install "))
                .unwrap_or_default();
            args.set("name", component.to_owned());
            keys::WEB_MIGRATE_REASON_COMPONENT
        }
        (
            None,
            "migration-reason-default-copy"
            | "migration-reason-copy-secret"
            | "migration-reason-non-critical-description",
        ) => keys::MIGRATE_REASON_COPY,
        (None, "migration-reason-remap-reference") => keys::MIGRATE_REASON_REMAP,
        (
            None,
            "migration-reason-hardware-led"
            | "migration-reason-hardware-button"
            | "migration-reason-hardware-usb"
            | "migration-reason-hardware-radio"
            | "migration-reason-hardware-printer",
        ) => keys::MIGRATE_REASON_SKIP_HARDWARE,
        (
            None,
            "migration-reason-identity-ndns"
            | "migration-reason-identity-cloud"
            | "migration-reason-identity-certificate"
            | "migration-reason-identity-mws"
            | "migration-reason-preflight-agreement"
            | "migration-reason-kernel-tunable"
            | "migration-reason-identity-mac",
        ) => keys::MIGRATE_REASON_SKIP_IDENTITY,
        (None, _) => keys::MIGRATE_REASON_UNSUPPORTED,
    };
    tr(locale, key, Some(&args))
}

/// The `index`-th word of `line`, or nothing.
fn word(line: &str, index: usize) -> String {
    line.split_whitespace()
        .nth(index)
        .unwrap_or_default()
        .to_owned()
}
