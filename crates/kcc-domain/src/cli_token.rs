//! Conservative unquoted router CLI tokens.

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
