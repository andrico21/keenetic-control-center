//! Stable wire names of the router and catalog enums kcc reports, never their `Debug` text.

use kcc_catalog::CommandKind;
use kcc_rci::{
    Level,
    capabilities::{Brand, SystemMode},
};

/// The wire name of a catalog command kind.
pub(crate) const fn command_kind(kind: CommandKind) -> &'static str {
    match kind {
        CommandKind::Setting => "setting",
        CommandKind::Show => "show",
        CommandKind::Action => "action",
        // A kind this version does not know.
        _ => "unknown",
    }
}

/// The wire name of a router status level.
pub(crate) const fn level(level: Level) -> &'static str {
    match level {
        Level::Message => "message",
        Level::Warning => "warning",
        Level::Error => "error",
        // A level this version does not know.
        _ => "unknown",
    }
}

/// The wire name of a router brand.
pub(crate) const fn brand(brand: Brand) -> &'static str {
    match brand {
        Brand::Keenetic => "keenetic",
        Brand::Netcraze => "netcraze",
        // `Unknown`, or a brand this version does not know.
        Brand::Unknown | _ => "unknown",
    }
}

/// The wire name of a router system mode: kcc's name for a mode it knows, the router's
/// own (lowercased) name for one it does not.
pub(crate) fn system_mode(mode: &SystemMode) -> &str {
    match mode {
        SystemMode::Router => "router",
        SystemMode::Extender => "extender",
        SystemMode::Ap => "ap",
        SystemMode::Repeater => "repeater",
        SystemMode::Other(name) => name,
        // A mode this version does not know.
        _ => "unknown",
    }
}
