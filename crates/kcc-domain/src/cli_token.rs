//! Router CLI tokens: conservative unquoted ones, and quoted words.

use kcc_config::quoting::{quote_cli_text, quote_cli_word};
use secrecy::ExposeSecret as _;

use crate::{DomainError, Result};

/// Refuses characters that would introduce another CLI token or command.
pub(crate) fn validate(value: &str) -> Result<()> {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || value.contains(['\'', '"', '\\', ';', '|'])
    {
        return Err(DomainError::InvalidCliToken);
    }
    Ok(())
}

/// `value` as one double-quoted CLI word with `"` and `\` escaped, for a short value (a
/// name, an identifier, an SSID); refuses control characters and values over the shared
/// 256-byte bound.
pub(crate) fn quoted(value: &str) -> Result<String> {
    quote_cli_word(value)
        .map(|word| word.expose_secret().to_owned())
        .map_err(|_error| DomainError::InvalidCliToken)
}

/// `text` as one double-quoted CLI word like [`quoted`], for free text (a description)
/// with no byte bound of its own; refuses control characters.
pub(crate) fn quoted_text(text: &str) -> Result<String> {
    quote_cli_text(text).map_err(|_error| DomainError::InvalidCliToken)
}
