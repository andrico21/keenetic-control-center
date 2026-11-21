//! The expiry choices of the API key create form.

use kcc_app::api_keys::{ApiKeyError, expires_after};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

/// The offered lifetimes: the form value (a humantime duration, empty for none) and its
/// label.
const CHOICES: [(&str, MessageKey); 5] = [
    ("", keys::WEB_ADMIN_KEY_EXPIRES_NEVER),
    ("7d", keys::WEB_ADMIN_KEY_EXPIRES_7D),
    ("30d", keys::WEB_ADMIN_KEY_EXPIRES_30D),
    ("90d", keys::WEB_ADMIN_KEY_EXPIRES_90D),
    ("1y", keys::WEB_ADMIN_KEY_EXPIRES_1Y),
];

/// One option of the expiry select.
pub(super) struct ExpiryOption {
    /// Form value.
    value: &'static str,
    /// Display label.
    label: String,
    /// Whether it is selected.
    selected: bool,
}

impl ExpiryOption {
    /// Form value.
    pub(super) const fn value(&self) -> &str {
        self.value
    }

    /// Display label.
    pub(super) fn label(&self) -> &str {
        &self.label
    }

    /// Whether it is selected.
    pub(super) const fn selected(&self) -> bool {
        self.selected
    }
}

/// The options in `locale`, `selected` chosen (the first when it is none of them).
pub(super) fn options(locale: Locale, selected: &str) -> Vec<ExpiryOption> {
    let known = CHOICES.iter().any(|&(value, _)| value == selected);
    CHOICES
        .iter()
        .enumerate()
        .map(|(index, &(value, label))| ExpiryOption {
            value,
            label: tr(locale, label, None),
            selected: if known { value == selected } else { index == 0 },
        })
        .collect()
}

/// The expiry the form value `choice` sets for a key created at `now`: none for the
/// empty choice.
///
/// # Errors
///
/// [`ApiKeyError::InvalidExpiry`] for a value that is not one of the offered choices.
pub(super) fn chosen(now: u64, choice: &str) -> Result<Option<u64>, ApiKeyError> {
    match CHOICES.iter().find(|&&(value, _)| value == choice) {
        None => Err(ApiKeyError::InvalidExpiry),
        Some(&("", _)) => Ok(None),
        Some(&(lifetime, _)) => expires_after(now, lifetime).map(Some),
    }
}
