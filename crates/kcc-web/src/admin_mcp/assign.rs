//! Small parsers of posted values and the rule that a change sets only what differs.

use core::time::Duration;

use serde::{
    Deserialize,
    de::value::{Error, StrDeserializer},
};
use url::{ParseError, Url};

/// Sets `slot` to `new` when it differs from `current`.
pub(super) fn set<T>(slot: &mut Option<T>, current: &T, new: T)
where
    T: PartialEq,
{
    if new != *current {
        *slot = Some(new);
    }
}

/// Sets `slot` to `new` when there is one and it differs from `current`; an empty field
/// clears nothing.
pub(super) fn set_optional<T>(slot: &mut Option<T>, current: Option<&T>, new: Option<T>)
where
    T: PartialEq,
{
    if let Some(value) = new.filter(|value| current != Some(value)) {
        *slot = Some(value);
    }
}

/// A checkbox: `on` when ticked, absent when not.
pub(super) fn check(text: &str) -> Option<bool> {
    match text {
        "" => Some(false),
        "on" => Some(true),
        _ => None,
    }
}

/// A non-empty text; an empty one sets nothing.
pub(super) fn filled(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_owned())
}

/// An absolute URL, or `None` for an empty field.
///
/// # Errors
///
/// The text is not an absolute URL.
pub(super) fn url(text: &str) -> Result<Option<Url>, ParseError> {
    if text.is_empty() {
        return Ok(None);
    }
    Url::parse(text).map(Some)
}

/// A lifetime such as `15m` or `7d`.
pub(super) fn lifetime(text: &str) -> Option<Duration> {
    humantime::parse_duration(text).ok()
}

/// A choice by its serde name, such as `self_signed`.
pub(super) fn choice<'de, T>(text: &'de str) -> Option<T>
where
    T: Deserialize<'de>,
{
    T::deserialize(StrDeserializer::<Error>::new(text)).ok()
}
