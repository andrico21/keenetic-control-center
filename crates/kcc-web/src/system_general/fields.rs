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
}

impl Field {
    /// The setting named by the route segment `slug`.
    pub(crate) fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "hostname" => Some(Self::Hostname),
            "description" => Some(Self::Description),
            _ => None,
        }
    }

    /// The route segment.
    const fn slug(self) -> &'static str {
        match self {
            Self::Hostname => "hostname",
            Self::Description => "description",
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
        }
    }

    /// The setting's dialog on `router`, posting back to its own route.
    pub(crate) fn dialog(self, router: &str, locale: Locale) -> FieldDialog {
        let post_to = format!("/ui/r/{router}/system/general/{}", self.slug());
        let dialog = FieldDialog::new(fragment_shell(locale), post_to, self.words());
        match self {
            Self::Hostname => dialog.with_help(keys::WEB_SYSTEM_HOSTNAME_HELP),
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
        }
    }

    /// The setting's current value in `general`, for the dialog.
    pub(crate) fn current(self, general: &General) -> String {
        match self {
            Self::Hostname => general.hostname(),
            Self::Description => general.description(),
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
        };
        if valid {
            Ok(value.to_owned())
        } else {
            Err(match self {
                Self::Hostname => keys::WEB_SYSTEM_HOSTNAME_ERROR,
                Self::Description => keys::WEB_SYSTEM_DESCRIPTION_ERROR,
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
    }
}
