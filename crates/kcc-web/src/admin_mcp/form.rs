//! A posted change of the MCP settings: the keys a section form edits, their values and
//! the password, parsed into the overrides that differ from the effective settings.

use core::str::FromStr as _;

use kcc_app::mcp_settings::{Effective, Source, document::McpOverrides, keys::KeyPath};
use secrecy::SecretString;

use super::keyed;

/// Field names besides the keys' own.
const NAMES: [&str; 8] = [
    "field",
    "key",
    "password",
    "revision",
    "mapping_claim",
    "mapping_role",
    "scope_name",
    "scope_role",
];

/// Why a posted change cannot be planned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FormError {
    /// A field the settings do not have, such as a file path.
    UnknownField,
    /// The value of the key cannot be used.
    Value(KeyPath),
    /// An environment variable sets the key.
    Env(KeyPath),
    /// `[mcp] locked` names the key.
    Locked(KeyPath),
}

/// A posted change: the form's pairs, the keys it edits and the password, if typed.
pub(crate) struct Submitted<'form> {
    /// Every pair as posted.
    pairs: &'form [(String, String)],
    /// The keys the form edits, in posting order, without repeats.
    fields: Vec<KeyPath>,
    /// The password typed into the confirmation, if any.
    password: Option<SecretString>,
    /// The settings revision the form was rendered from, if posted.
    revision: Option<u64>,
}

impl<'form> Submitted<'form> {
    /// Parses `pairs`, refusing any field name the settings do not have.
    ///
    /// # Errors
    ///
    /// [`FormError::UnknownField`] for a field name, or a `field` value, the settings do
    /// not have, or a `revision` that is not a number.
    pub(crate) fn parse(pairs: &'form [(String, String)]) -> Result<Self, FormError> {
        let mut fields = Vec::new();
        let mut password = None;
        let mut revision = None;
        for (name, value) in pairs {
            match name.as_str() {
                "field" => {
                    let key =
                        KeyPath::from_str(value).map_err(|_unknown| FormError::UnknownField)?;
                    if !fields.contains(&key) {
                        fields.push(key);
                    }
                }
                "password" => password = Some(SecretString::from(value.clone())),
                "revision" => {
                    revision = Some(value.parse().map_err(|_nan| FormError::UnknownField)?);
                }
                other if NAMES.contains(&other) || KeyPath::from_str(other).is_ok() => {}
                _ => return Err(FormError::UnknownField),
            }
        }
        Ok(Self {
            pairs,
            fields,
            password,
            revision,
        })
    }

    /// The password typed into the confirmation, if any.
    pub(crate) const fn password(&self) -> Option<&SecretString> {
        self.password.as_ref()
    }

    /// The settings revision the form was rendered from, if posted.
    pub(crate) const fn revision(&self) -> Option<u64> {
        self.revision
    }

    /// The first value posted as `name`.
    pub(crate) fn value(&self, name: &str) -> Option<&'form str> {
        self.pairs
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.as_str())
    }

    /// Every value posted as `name`, in order.
    fn values(&self, name: &str) -> Vec<&'form str> {
        self.pairs
            .iter()
            .filter(|(field, _)| field == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// The overrides of every edited key whose posted value differs from `effective`.
    ///
    /// # Errors
    ///
    /// [`FormError::Env`] or [`FormError::Locked`] for a key the page shows as text only,
    /// [`FormError::Value`] for a value that does not parse.
    pub(crate) fn change(&self, effective: &Effective) -> Result<McpOverrides, FormError> {
        let mut change = McpOverrides::default();
        for key in self.fields.iter().copied() {
            match effective.source(key) {
                Source::Env => return Err(FormError::Env(key)),
                Source::Locked => return Err(FormError::Locked(key)),
                Source::State | Source::Toml | Source::Default | _ => {}
            }
            keyed::assign(self, key, (effective, &mut change)).ok_or(FormError::Value(key))?;
        }
        Ok(change)
    }

    /// The values of a checkbox list `key`, without repeats.
    pub(crate) fn list(&self, key: KeyPath) -> Vec<String> {
        let mut items: Vec<String> = Vec::new();
        for value in self.values(key.as_str()) {
            if !items.iter().any(|item| item == value) {
                items.push(value.to_owned());
            }
        }
        items
    }

    /// The `(first, role)` rows of a mapping table; a row with an empty first field is
    /// dropped, one with an empty role refused.
    pub(crate) fn rows(&self, (first, second): (&str, &str)) -> Option<Vec<(String, String)>> {
        let mut rows = Vec::new();
        for (typed, chosen) in self.values(first).into_iter().zip(self.values(second)) {
            let (value, role) = (typed.trim(), chosen.trim());
            if value.is_empty() {
                continue;
            }
            if role.is_empty() {
                return None;
            }
            rows.push((value.to_owned(), role.to_owned()));
        }
        Some(rows)
    }
}
