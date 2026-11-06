//! The settings the general page edits in one-field dialogs: how each is checked before
//! anything is sent, and how the system domain plans its change.

use kcc_domain::{ChangeOp, Result as DomainResult, RouterCtx, system};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};
use serde::Deserialize;

use super::general::General;
use crate::page_kit::{action::Operation, context::fragment_shell, dialog::FieldDialog};

/// Longest description accepted, in characters.
const DESCRIPTION_CHARS: usize = 128;

/// Longest host name accepted, in bytes (one DNS label).
const HOSTNAME_BYTES: usize = 63;

/// Longest time-zone name accepted, in bytes.
const TIMEZONE_BYTES: usize = 64;

/// Longest time-server name accepted, in bytes (one DNS name).
const SERVER_BYTES: usize = 253;

/// The value submitted from a one-field dialog.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ValueForm {
    /// The value as typed.
    #[serde(default)]
    value: String,
}

impl ValueForm {
    /// The value as typed.
    pub(crate) fn value(&self) -> &str {
        &self.value
    }
}

/// A setting the general page edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Field {
    /// The router's host name.
    Hostname,
    /// The router's free-text description.
    Description,
    /// The time zone, such as `Europe/Berlin`.
    Timezone,
    /// The time server the router synchronizes with.
    NtpServer,
}

impl Field {
    /// The setting named by the route segment `slug`.
    pub(crate) fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "hostname" => Some(Self::Hostname),
            "description" => Some(Self::Description),
            "timezone" => Some(Self::Timezone),
            "ntp_server" => Some(Self::NtpServer),
            _ => None,
        }
    }

    /// The route segment.
    const fn slug(self) -> &'static str {
        match self {
            Self::Hostname => "hostname",
            Self::Description => "description",
            Self::Timezone => "timezone",
            Self::NtpServer => "ntp_server",
        }
    }

    /// The system domain's write, with its audit action id.
    pub(crate) const fn operation(self) -> Operation {
        match self {
            Self::Hostname => {
                Operation::write(&system::DESCRIPTOR, "hostname", "web.system_hostname")
            }
            Self::Description => {
                Operation::write(&system::DESCRIPTOR, "description", "web.system_description")
            }
            Self::Timezone => {
                Operation::write(&system::DESCRIPTOR, "timezone", "web.system_timezone")
            }
            Self::NtpServer => {
                Operation::write(&system::DESCRIPTOR, "ntp_server", "web.system_ntp_server")
            }
        }
    }

    /// The setting's dialog on `router`, posting back to its own route.
    pub(crate) fn dialog(self, router: &str, locale: Locale) -> FieldDialog {
        let post_to = format!("/ui/r/{router}/system/general/{}", self.slug());
        let dialog = FieldDialog::new(fragment_shell(locale), post_to, self.words());
        match self {
            Self::Hostname => dialog.with_help(keys::WEB_SYSTEM_HOSTNAME_HELP),
            Self::Timezone => dialog.with_help(keys::WEB_SYSTEM_TIMEZONE_HELP),
            Self::NtpServer => dialog.with_help(keys::WEB_SYSTEM_NTP_SERVER_HELP),
            Self::Description => dialog,
        }
    }

    /// The dialog's title and the field's label.
    const fn words(self) -> (MessageKey, MessageKey) {
        match self {
            Self::Hostname => (
                keys::WEB_SYSTEM_HOSTNAME_TITLE,
                keys::WEB_DASHBOARD_HOSTNAME,
            ),
            Self::Description => (
                keys::WEB_SYSTEM_DESCRIPTION_TITLE,
                keys::WEB_SYSTEM_DESCRIPTION,
            ),
            Self::Timezone => (keys::WEB_SYSTEM_TIMEZONE_TITLE, keys::WEB_SYSTEM_TIMEZONE),
            Self::NtpServer => (
                keys::WEB_SYSTEM_NTP_SERVER_TITLE,
                keys::WEB_SYSTEM_NTP_SERVER,
            ),
        }
    }

    /// The setting's current value in `general`, for the dialog.
    pub(crate) fn current(self, general: &General) -> String {
        match self {
            Self::Hostname => general.hostname(),
            Self::Description => general.description(),
            Self::Timezone => general.timezone(),
            Self::NtpServer => general.ntp_server(),
        }
        .unwrap_or_default()
        .to_owned()
    }

    /// The submitted `input`, trimmed, when it is a valid value; else the message saying
    /// what a valid one looks like.
    ///
    /// # Errors
    ///
    /// Returns the field's error message.
    pub(crate) fn check(self, input: &str) -> Result<String, MessageKey> {
        let value = input.trim();
        let valid = match self {
            Self::Hostname => is_hostname(value),
            Self::Description => {
                (1..=DESCRIPTION_CHARS).contains(&value.chars().count())
                    && !value.chars().any(char::is_control)
            }
            Self::Timezone => is_timezone(value),
            Self::NtpServer => is_server(value),
        };
        if valid {
            Ok(value.to_owned())
        } else {
            Err(match self {
                Self::Hostname => keys::WEB_SYSTEM_HOSTNAME_ERROR,
                Self::Description => keys::WEB_SYSTEM_DESCRIPTION_ERROR,
                Self::Timezone => keys::WEB_SYSTEM_TIMEZONE_ERROR,
                Self::NtpServer => keys::WEB_SYSTEM_NTP_SERVER_ERROR,
            })
        }
    }

    /// The system domain's plan setting the field to `value` on the router of `domain`.
    ///
    /// # Errors
    ///
    /// Returns the catalog's findings.
    pub(crate) fn plan(self, domain: &RouterCtx, value: &str) -> DomainResult<ChangeOp> {
        match self {
            Self::Hostname => system::plan_hostname(domain, value),
            Self::Description => system::plan_description(domain, value),
            Self::Timezone => system::plan_timezone(domain, value),
            Self::NtpServer => system::plan_ntp_server(domain, value),
        }
    }
}

/// Whether `value` is one DNS label: 1 to 63 Latin letters, digits and hyphens, with no
/// hyphen first or last.
fn is_hostname(value: &str) -> bool {
    (1..=HOSTNAME_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

/// Whether `value` is a time-zone name: Latin letters, digits and `_ + - /`, with no
/// slash first or last, such as `Europe/Berlin` or `UTC`.
fn is_timezone(value: &str) -> bool {
    (1..=TIMEZONE_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_+-/".contains(&byte))
        && !value.starts_with('/')
        && !value.ends_with('/')
}

/// Whether `value` names a time server: a DNS name or an IPv4 or IPv6 address, written
/// with Latin letters, digits, dots, hyphens and colons, starting with a letter or digit.
fn is_server(value: &str) -> bool {
    (1..=SERVER_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-:".contains(&byte))
        && value
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_i18n::keys;

    use super::Field;

    #[test]
    fn values_are_checked_before_anything_is_sent() {
        assert_eq!(
            Field::Hostname.check(" office-1 "),
            Ok("office-1".to_owned()),
            "trimmed label"
        );
        for bad in [
            "",
            "-office",
            "office-",
            "office 1",
            "office_1",
            &"a".repeat(64),
        ] {
            assert_eq!(
                Field::Hostname.check(bad),
                Err(keys::WEB_SYSTEM_HOSTNAME_ERROR),
                "{bad}"
            );
        }
        assert_eq!(
            Field::Description.check("Office, 2nd floor"),
            Ok("Office, 2nd floor".to_owned()),
            "free text"
        );
        for bad in ["  ", "line\nbreak", &"x".repeat(129)] {
            assert_eq!(
                Field::Description.check(bad),
                Err(keys::WEB_SYSTEM_DESCRIPTION_ERROR),
                "{bad}"
            );
        }
        assert_eq!(
            Field::Timezone.check("Europe/Berlin"),
            Ok("Europe/Berlin".to_owned()),
            "an area and a city"
        );
        for bad in ["", "Europe Berlin", "/UTC", "Etc/", "Europe;reboot"] {
            assert_eq!(
                Field::Timezone.check(bad),
                Err(keys::WEB_SYSTEM_TIMEZONE_ERROR),
                "{bad}"
            );
        }
        for good in ["pool.ntp.org", "192.0.2.10", "2001:db8::1"] {
            assert_eq!(Field::NtpServer.check(good), Ok(good.to_owned()), "{good}");
        }
        for bad in ["", ".pool", "time server", "ntp/1"] {
            assert_eq!(
                Field::NtpServer.check(bad),
                Err(keys::WEB_SYSTEM_NTP_SERVER_ERROR),
                "{bad}"
            );
        }
    }
}
