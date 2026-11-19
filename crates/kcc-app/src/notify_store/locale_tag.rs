//! Serde form of an optional [`Locale`]: its language tag, checked with
//! [`Locale::from_tag`].

use kcc_i18n::locale::Locale;
use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

use super::NotifyError;

/// Writes the tag, or `null`.
///
/// # Errors
///
/// Whatever `serializer` returns.
#[expect(
    clippy::ref_option,
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's `with` passes the field by reference"
)]
pub(super) fn serialize<S>(value: &Option<Locale>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(locale) => serializer.serialize_some(locale.tag()),
        None => serializer.serialize_none(),
    }
}

/// Reads a supported tag such as `kk` or `kk-KZ`, or `null`.
///
/// # Errors
///
/// A deserializer error naming only the field for an unsupported or malformed tag.
pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Option<Locale>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|tag| {
            Locale::from_tag(&tag)
                .ok_or_else(|| D::Error::custom(NotifyError::Invalid { field: "locale" }))
        })
        .transpose()
}
