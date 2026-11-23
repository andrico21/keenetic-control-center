//! The words of the Entware page for the router's state: why it cannot run Entware, its
//! components, its architecture and its time zone setting.

use fluent_bundle::FluentArgs;
use kcc_domain::entware::models::{
    ArchResolution, ComponentPresence, Possibility, TimezoneSetting,
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

/// The localized reason the router cannot run Entware, or `None` when it can.
pub(super) fn blocked(possible: &Possibility, locale: Locale) -> Option<String> {
    match possible {
        Possibility::Possible => None,
        Possibility::UnsupportedArch(arch) => {
            let mut args = FluentArgs::new();
            args.set("name", arch.clone());
            Some(tr(locale, keys::WEB_SYSTEM_ENTWARE_NO_ARCH, Some(&args)))
        }
        Possibility::NoUsbOrStorage | _ => Some(tr(locale, keys::WEB_SYSTEM_ENTWARE_NO_USB, None)),
    }
}

/// The label of a component's state; on a router that cannot run Entware (`blocked`) no
/// label promises the setup.
pub(super) const fn presence(component: ComponentPresence, blocked: bool) -> MessageKey {
    match (component, blocked) {
        (ComponentPresence::Installed, _) => keys::WEB_SYSTEM_ENTWARE_INSTALLED,
        (ComponentPresence::Available, false) => keys::WEB_SYSTEM_ENTWARE_AVAILABLE,
        (ComponentPresence::Available, true) => keys::WEB_SYSTEM_ENTWARE_NOT_INSTALLED,
        (ComponentPresence::Missing | _, _) => keys::WEB_SYSTEM_ENTWARE_MISSING,
    }
}

/// The architecture, localized; on a router that cannot run Entware (`blocked`) only the
/// name the router reports.
pub(super) fn arch(resolution: &ArchResolution, blocked: bool, locale: Locale) -> String {
    match (resolution, blocked) {
        (ArchResolution::Aarch64, false) => tr(locale, keys::WEB_SYSTEM_ENTWARE_ARCH_AARCH64, None),
        (ArchResolution::MipsAmbiguous, false) => {
            tr(locale, keys::WEB_SYSTEM_ENTWARE_ARCH_MIPS, None)
        }
        (ArchResolution::Aarch64, true) => "aarch64".to_owned(),
        (ArchResolution::MipsAmbiguous, true) => "mips".to_owned(),
        (ArchResolution::Unknown(name), _) => name.clone(),
        _ => tr(locale, keys::WEB_KIT_NOT_REPORTED, None),
    }
}

/// The time zone setting, localized.
pub(super) fn timezone(setting: &TimezoneSetting, locale: Locale) -> String {
    match setting {
        TimezoneSetting::Named(name) => name.clone(),
        TimezoneSetting::Auto | _ => tr(locale, keys::WEB_SYSTEM_ENTWARE_TIMEZONE_AUTO, None),
    }
}
