//! The text of every notification, in the chosen language. Usernames, router ids,
//! actions and client names go in as plain text: messages are sent without a parse mode,
//! so nothing in them is markup.

use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    format, keys,
    locale::Locale,
};

use super::audits::ChangeFailure;

/// `key` in `locale` with the named string arguments.
fn line(locale: Locale, key: MessageKey, values: &[(&'static str, &str)]) -> String {
    let mut args = FluentArgs::new();
    for &(name, value) in values {
        args.set(name, value.to_owned());
    }
    tr(locale, key, Some(&args))
}

/// Router `router` is offline since `since` (local time).
pub(super) fn router_down(locale: Locale, router: &str, since: &str) -> String {
    line(
        locale,
        keys::NOTIFY_ROUTER_DOWN,
        &[("router", router), ("time", since)],
    )
}

/// Router `router` is back after `outage` seconds.
pub(super) fn router_up(locale: Locale, router: &str, outage: u64) -> String {
    let duration = format::duration(locale, outage);
    line(
        locale,
        keys::NOTIFY_ROUTER_UP,
        &[("router", router), ("duration", &duration)],
    )
}

/// Router `router` refused kcc's login.
pub(super) fn router_login(locale: Locale, router: &str) -> String {
    line(locale, keys::NOTIFY_ROUTER_LOGIN, &[("router", router)])
}

/// Firmware `version` is available for `router`.
pub(super) fn firmware(locale: Locale, router: &str, version: &str) -> String {
    line(
        locale,
        keys::NOTIFY_FIRMWARE,
        &[("router", router), ("version", version)],
    )
}

/// New unregistered devices on `router`, already named as the settings say.
pub(super) fn new_devices(locale: Locale, router: &str, devices: &[String]) -> String {
    line(
        locale,
        keys::NOTIFY_NEW_DEVICES,
        &[("router", router), ("devices", &devices.join(", "))],
    )
}

/// A client named `name` with the MAC `mac`, for messages with client details.
pub(super) fn client_details(locale: Locale, name: &str, mac: &str) -> String {
    line(
        locale,
        keys::NOTIFY_CLIENT_DETAILS,
        &[("name", name), ("address", mac)],
    )
}

/// A change failed on the router `named` (its display name), if it had one; says so
/// when the router's fail-safe timer is still armed.
pub(super) fn change_failed(
    locale: Locale,
    failure: &ChangeFailure,
    named: Option<&str>,
) -> String {
    let mut text = named.map_or_else(
        || {
            line(
                locale,
                keys::NOTIFY_CHANGE_FAILED_FLEET,
                &[("action", failure.action()), ("actor", failure.actor())],
            )
        },
        |router| {
            line(
                locale,
                keys::NOTIFY_CHANGE_FAILED,
                &[
                    ("action", failure.action()),
                    ("router", router),
                    ("actor", failure.actor()),
                ],
            )
        },
    );
    if failure.fail_safe_armed() {
        text.push(' ');
        text.push_str(&tr(locale, keys::NOTIFY_CHANGE_FAIL_SAFE, None));
    }
    text
}

/// Account `user` is locked until `until` (local time).
pub(super) fn account_locked(locale: Locale, user: &str, until: &str) -> String {
    line(
        locale,
        keys::NOTIFY_ACCOUNT_LOCKED,
        &[("user", user), ("time", until)],
    )
}

/// The audit log was repaired; the torn entry is in `file`.
pub(super) fn audit_repaired(locale: Locale, file: &str) -> String {
    line(locale, keys::NOTIFY_AUDIT_REPAIRED, &[("file", file)])
}

/// The audit writer stopped.
pub(super) fn audit_stopped(locale: Locale) -> String {
    tr(locale, keys::NOTIFY_AUDIT_STOPPED, None)
}

/// A job of `kind` failed, on `router` when it has one.
pub(super) fn job_failed(locale: Locale, kind: &str, router: Option<&str>) -> String {
    router.map_or_else(
        || line(locale, keys::NOTIFY_JOB_FAILED_FLEET, &[("kind", kind)]),
        |name| {
            line(
                locale,
                keys::NOTIFY_JOB_FAILED,
                &[("kind", kind), ("router", name)],
            )
        },
    )
}

/// `count` lines were dropped.
pub(super) fn dropped(locale: Locale, count: u64) -> String {
    let shown = format::integer(locale, count);
    line(locale, keys::NOTIFY_DROPPED, &[("count", &shown)])
}

/// The test message.
pub(super) fn test(locale: Locale) -> String {
    tr(locale, keys::NOTIFY_TEST, None)
}
