//! The checks of the firewall dialogs' values, at the boundary.
//!
//! List names and schedule names are one CLI word, addresses IPv4, descriptions printable
//! and free of quotes. Ports and masks use the shared [`crate::page_kit::values`] checks.

use core::net::Ipv4Addr;

use kcc_i18n::{bundle::MessageKey, keys};
use kcc_rci::ObjectName;

/// Longest description, in characters.
const DESCRIPTION_CHARS: usize = 64;

/// Whether `text` is an access-list name the page writes into a CLI line: one word of
/// letters, digits and `- _ . : /`, at most 64 characters.
pub(crate) fn list_name(text: &str) -> bool {
    text.parse::<ObjectName>().is_ok()
}

/// Whether `text` is an IPv4 address.
pub(crate) fn address(text: &str) -> bool {
    text.parse::<Ipv4Addr>().is_ok()
}

/// An optional description: printable, without quotes or backslashes, at most 64
/// characters; empty is none.
///
/// # Errors
///
/// Returns the description rule.
pub(crate) fn description(text: &str) -> Result<Option<String>, MessageKey> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let printable = trimmed
        .chars()
        .all(|character| !character.is_control() && !matches!(character, '"' | '\'' | '\\'));
    if printable && trimmed.chars().count() <= DESCRIPTION_CHARS {
        Ok(Some(trimmed.to_owned()))
    } else {
        Err(keys::WEB_FIREWALL_ERROR_DESCRIPTION)
    }
}
