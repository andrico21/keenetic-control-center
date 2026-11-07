//! The checks of the firewall dialogs' values, at the boundary: list names and schedule
//! names are one CLI word, addresses and masks IPv4, ports from 1 to 65535, descriptions
//! printable and free of quotes.

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

/// An optional port from 1 to 65535.
///
/// # Errors
///
/// Returns the port rule.
pub(crate) fn port(text: &str) -> Result<Option<u16>, MessageKey> {
    if text.is_empty() {
        return Ok(None);
    }
    match text.parse::<u16>() {
        Ok(found) if found > 0 => Ok(Some(found)),
        Ok(_) | Err(_) => Err(keys::WEB_ROUTING_ERROR_PORT),
    }
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
