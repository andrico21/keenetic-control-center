//! How the wizard words a classified setting: what happens to it and why.

use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_migrate::rules::{
    ClassifiedItem, Disposition,
    reason::{NeededInput, Reason},
};

use super::warnings::component;

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
    let key = match (conflict, item.reason) {
        (Some(Resolution::Source), _) => keys::WEB_MIGRATE_REASON_CONFLICT_SOURCE,
        (Some(Resolution::Router), _) => keys::WEB_MIGRATE_REASON_CONFLICT_ROUTER,
        (Some(Resolution::Undecided), _) | (None, Reason::ScalarConflict) => {
            keys::WEB_MIGRATE_REASON_CONFLICT
        }
        (None, Reason::PasswordRealm) => {
            args.set("name", password_user(item).to_owned());
            if item.disposition == Disposition::NeedsInput {
                keys::WEB_MIGRATE_REASON_PASSWORD
            } else {
                keys::WEB_MIGRATE_REASON_PASSWORD_SET
            }
        }
        (None, Reason::InstallComponent) => {
            args.set("name", component(item).unwrap_or_default().to_owned());
            keys::WEB_MIGRATE_REASON_COMPONENT
        }
        (None, Reason::DefaultCopy | Reason::CopySecret | Reason::NonCriticalDescription) => {
            keys::MIGRATE_REASON_COPY
        }
        (None, Reason::RemapReference) => keys::MIGRATE_REASON_REMAP,
        (
            None,
            Reason::HardwareLed
            | Reason::HardwareButton
            | Reason::HardwareUsb
            | Reason::HardwareRadio
            | Reason::HardwarePrinter
            | Reason::HardwareInterface
            | Reason::HardwareEntware,
        ) => keys::MIGRATE_REASON_SKIP_HARDWARE,
        (
            None,
            Reason::IdentityNdns
            | Reason::IdentityCloud
            | Reason::IdentityCertificate
            | Reason::IdentityMws
            | Reason::PreflightAgreement
            | Reason::KernelTunable
            | Reason::IdentityMac,
        ) => keys::MIGRATE_REASON_SKIP_IDENTITY,
        (None, Reason::ManagementReconnect) => keys::MIGRATE_REASON_NEEDS_INPUT,
        (None, Reason::UnsupportedCommand) => keys::MIGRATE_REASON_UNSUPPORTED,
    };
    tr(locale, key, Some(&args))
}

/// The router user whose password `item` depends on, or nothing.
pub(super) fn password_user(item: &ClassifiedItem) -> &str {
    match &item.input {
        Some(NeededInput::Password { user }) => user,
        Some(NeededInput::Install { component: _ } | NeededInput::ReconnectUrl) | None => "",
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use alloc::collections::{BTreeMap, BTreeSet};
    use core::error::Error;

    use kcc_config::config_text::parse;
    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_migrate::{
        maps::{InterfaceMap, PortMap, RadioMap},
        rules::{ClassificationChoices, ClassificationTarget, InterfaceInventory, classify},
    };

    use super::reason;

    /// W5-08: a bridge member the target lacks reads as skipped hardware.
    ///
    /// The wizard did not list this engine reason, so it read as "unsupported" through a
    /// wildcard arm.
    #[test]
    fn a_missing_bridge_member_reads_as_skipped_hardware() -> Result<(), Box<dyn Error>> {
        let source = parse("interface Bridge0 include GigabitEthernet0/4\n")?;
        let target = parse("")?;
        let (installed, overwrites) = (BTreeSet::new(), BTreeSet::new());
        let interfaces = BTreeSet::from(["GigabitEthernet0/3".to_owned()]);
        let (ports, radios, names) = (
            PortMap::default(),
            RadioMap::default(),
            InterfaceMap::default(),
        );
        let passwords = BTreeMap::new();
        let choices = ClassificationChoices::new(&ports, &radios, &names, &passwords, &overwrites);
        let view = ClassificationTarget::new(
            None,
            &target,
            &installed,
            None,
            InterfaceInventory::Available(&interfaces),
        );
        let items = classify(&source, view, &choices)?;
        let member = items.last().ok_or("no item")?;

        assert_eq!(
            reason(member, None, Locale::En),
            tr(Locale::En, keys::MIGRATE_REASON_SKIP_HARDWARE, None)
        );
        Ok(())
    }
}
