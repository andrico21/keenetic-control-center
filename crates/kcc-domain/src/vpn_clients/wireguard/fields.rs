//! WireGuard field parsing and duplicate checks.

use alloc::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use secrecy::SecretString;

use super::wireguard::WireGuardParseError;

/// Parses a fixed-size WireGuard key into protected storage.
pub(super) fn set_secret(
    slot: &mut Option<SecretString>,
    field: &str,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    validate_key(field, value, line)?;
    if slot.replace(SecretString::from(value.to_owned())).is_some() {
        return Err(duplicate(line));
    }
    Ok(())
}

/// Parses a printable obfuscation key without imposing a Base64 format.
pub(super) fn set_obfuscation(
    slot: &mut Option<SecretString>,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(WireGuardParseError::Malformed { line });
    }
    if slot.replace(SecretString::from(value.to_owned())).is_some() {
        return Err(duplicate(line));
    }
    Ok(())
}

/// Parses a public key and refuses duplicates.
pub(super) fn set_public_key(
    slot: &mut Option<String>,
    field: &str,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    validate_key(field, value, line)?;
    set_string(slot, value, line)
}

/// Checks the decoded WireGuard key length.
fn validate_key(field: &str, value: &str, line: usize) -> Result<(), WireGuardParseError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_error| WireGuardParseError::InvalidKey {
            line,
            field: field.to_owned(),
        })?;
    if decoded.len() != 32 {
        return Err(WireGuardParseError::InvalidKey {
            line,
            field: field.to_owned(),
        });
    }
    Ok(())
}

/// Parses one integer field and refuses duplicates.
pub(super) fn set_integer(
    slot: &mut Option<u16>,
    field: &str,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    let parsed = value
        .parse::<u16>()
        .map_err(|_error| WireGuardParseError::InvalidInteger {
            line,
            field: field.to_owned(),
        })?;
    if slot.replace(parsed).is_some() {
        return Err(duplicate(line));
    }
    Ok(())
}

/// Stores one string field and refuses duplicates.
pub(super) fn set_string(
    slot: &mut Option<String>,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    if slot.replace(value.to_owned()).is_some() {
        return Err(duplicate(line));
    }
    Ok(())
}

/// Parses a comma-separated list and refuses duplicates.
pub(super) fn set_list(
    slot: &mut Option<Vec<String>>,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    if slot
        .replace(value.split(',').map(str::trim).map(str::to_owned).collect())
        .is_some()
    {
        return Err(duplicate(line));
    }
    Ok(())
}

/// Stores one ASC field and refuses duplicates.
pub(super) fn insert_once(
    fields: &mut BTreeMap<String, String>,
    field: &str,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    if fields.insert(field.to_owned(), value.to_owned()).is_some() {
        return Err(duplicate(line));
    }
    Ok(())
}

/// Recognizes the supported ASC field names.
pub(super) const fn is_asc_field(field: &str) -> bool {
    matches!(
        field.as_bytes(),
        b"Jc"
            | b"Jmin"
            | b"Jmax"
            | b"S1"
            | b"S2"
            | b"S3"
            | b"S4"
            | b"H1"
            | b"H2"
            | b"H3"
            | b"H4"
            | b"I1"
            | b"I2"
            | b"I3"
            | b"I4"
            | b"I5"
    )
}

/// Reports a duplicate by line number only.
pub(super) const fn duplicate(line: usize) -> WireGuardParseError {
    WireGuardParseError::Duplicate { line }
}
