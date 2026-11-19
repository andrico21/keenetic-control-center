//! The text values of a schedule, each parsed once at the boundary.

use serde::{Deserialize, Serialize};

/// A rejected schedule field; names only the field, never the rejected value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum FieldError {
    /// The name is empty, longer than 64 characters or holds a control character.
    #[error("invalid name")]
    Name,
    /// The MAC is not six pairs of hex digits.
    #[error("invalid mac")]
    Mac,
    /// The policy is not 1 to 64 letters, digits, `-`, `_` or `.`.
    #[error("invalid policy")]
    Policy,
    /// The preset id is not 1 to 64 ASCII letters, digits, `-` or `_`.
    #[error("invalid preset id")]
    PresetId,
}

/// Longest name, policy or preset id, in characters.
const MAX_CHARS: usize = 64;

/// Whether `value` has 1 to 64 characters, each accepted by `allowed`.
fn bounded(value: &str, allowed: fn(char) -> bool) -> bool {
    (1..=MAX_CHARS).contains(&value.chars().count()) && value.chars().all(allowed)
}

/// Declares a string newtype that is parsed on construction and on deserialization.
macro_rules! parsed_text {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        #[non_exhaustive]
        pub struct $name(String);

        impl TryFrom<String> for $name {
            type Error = FieldError;

            #[inline]
            fn try_from(value: String) -> Result<Self, FieldError> {
                Self::parse(&value)
            }
        }

        impl From<$name> for String {
            #[inline]
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

parsed_text!(
    /// A schedule's display name: 1 to 64 characters, no control character.
    ScheduleName
);
parsed_text!(
    /// A client MAC: six pairs of lowercase hex digits separated by colons.
    ClientMac
);
parsed_text!(
    /// A connection policy name: 1 to 64 letters, digits, `-`, `_` or `.`, one word of the
    /// router's command line.
    PolicyName
);
parsed_text!(
    /// A preset id: 1 to 64 ASCII letters, digits, `-` or `_`, as the preset store accepts.
    PresetId
);

impl ScheduleName {
    /// Parses a name.
    ///
    /// # Errors
    ///
    /// [`FieldError::Name`].
    #[inline]
    pub fn parse(value: &str) -> Result<Self, FieldError> {
        bounded(value, |letter| !letter.is_control())
            .then(|| Self(value.to_owned()))
            .ok_or(FieldError::Name)
    }

    /// The name.
    #[must_use]
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ClientMac {
    /// Parses six pairs of hex digits separated by `:` or `-`, in any case, into the
    /// lowercase, colon-separated form.
    ///
    /// # Errors
    ///
    /// [`FieldError::Mac`].
    #[inline]
    pub fn parse(value: &str) -> Result<Self, FieldError> {
        let pairs = value.split([':', '-']).collect::<Vec<_>>();
        let valid = pairs.len() == 6
            && pairs
                .iter()
                .all(|pair| pair.len() == 2 && pair.bytes().all(|byte| byte.is_ascii_hexdigit()));
        valid
            .then(|| Self(pairs.join(":").to_ascii_lowercase()))
            .ok_or(FieldError::Mac)
    }

    /// The MAC: lowercase, colon-separated.
    #[must_use]
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl PolicyName {
    /// Parses a policy name.
    ///
    /// # Errors
    ///
    /// [`FieldError::Policy`].
    #[inline]
    pub fn parse(value: &str) -> Result<Self, FieldError> {
        bounded(value, |letter| {
            letter.is_alphanumeric() || matches!(letter, '-' | '_' | '.')
        })
        .then(|| Self(value.to_owned()))
        .ok_or(FieldError::Policy)
    }

    /// The policy name.
    #[must_use]
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl PresetId {
    /// Parses a preset id.
    ///
    /// # Errors
    ///
    /// [`FieldError::PresetId`].
    #[inline]
    pub fn parse(value: &str) -> Result<Self, FieldError> {
        bounded(value, |letter| {
            letter.is_ascii_alphanumeric() || matches!(letter, '-' | '_')
        })
        .then(|| Self(value.to_owned()))
        .ok_or(FieldError::PresetId)
    }

    /// The preset id.
    #[must_use]
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
