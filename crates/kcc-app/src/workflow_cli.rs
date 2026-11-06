//! Secret-bearing CLI command ownership and structural argument binding.

use core::fmt;

use kcc_catalog::{SecretValue, ValidatedRequest};
use kcc_config::quoting::{QuoteError, quote_cli_word};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Serialize, Serializer};
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// A CLI command that retains plaintext only in zeroizing storage.
#[derive(Clone)]
#[non_exhaustive]
pub struct CliCommand {
    /// Owned command or structural template.
    line: SecretString,
    /// Catalog request retaining classified secret arguments.
    validated: ValidatedRequest,
    /// Whether the line contains JSON-pointer argument slots.
    template: bool,
}

/// Secret command construction failure, containing no rejected material.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretCommandError {
    /// A secret argument violates the printable CLI word contract.
    #[error(transparent)]
    Word(#[from] QuoteError),
    /// The template does not bind exactly the validated secret argument slots.
    #[error("secret CLI template does not match the validated command")]
    Template,
}

impl CliCommand {
    /// Preserves the existing constructor while moving the line into zeroizing storage.
    #[inline]
    #[must_use]
    pub fn new(line: String, validated: ValidatedRequest) -> Self {
        Self {
            line: SecretString::from(line),
            validated,
            template: false,
        }
    }

    /// Owns an explicitly secret line; its printable representations are always redacted.
    #[inline]
    #[must_use]
    pub fn secret(mut structural: ValidatedRequest, line: SecretString) -> Self {
        structural.protected.retain_scrubber(line.clone());
        Self {
            line,
            validated: structural,
            template: false,
        }
    }

    /// Binds `{/<argument>}` slots to catalog-validated secret values.
    ///
    /// For example `user guest password plain {/password}` binds `/password`.
    /// Context names must be single conservative CLI tokens. The actual secret is
    /// quoted only by [`Self::expose_for_send`]; this constructor validates its charset.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for invalid context syntax, missing/extra slots,
    /// uncatalogued requests, or secret words violating the quoting contract.
    #[inline]
    pub fn from_template(
        validated: ValidatedRequest,
        template: &str,
    ) -> Result<Self, SecretCommandError> {
        if validated.unvalidated
            || !validated.has_secrets()
            || template
                .chars()
                .any(|ch| ch.is_control() || matches!(ch, '"' | '\\' | '\'' | ';' | '|'))
        {
            return Err(SecretCommandError::Template);
        }
        let wire = validated.expose_for_send();
        let mut structural = Vec::new();
        let mut seen = Vec::new();
        for token in template.split_whitespace() {
            if let Some(pointer) = token
                .strip_prefix('{')
                .and_then(|word| word.strip_suffix('}'))
            {
                if !validated
                    .protected_value()
                    .secret_pointers()
                    .any(|known| known == pointer)
                    || seen.contains(&pointer)
                {
                    return Err(SecretCommandError::Template);
                }
                let value = wire
                    .expose_secret()
                    .pointer(pointer)
                    .and_then(Value::as_str)
                    .ok_or(SecretCommandError::Template)?;
                drop(quote_cli_word(value)?);
                seen.push(pointer);
            } else {
                if !seen.is_empty() {
                    return Err(SecretCommandError::Template);
                }
                structural.push(token);
            }
        }
        if seen.len() != validated.protected_value().secret_pointers().count() {
            return Err(SecretCommandError::Template);
        }
        let expected = validated.path.split_whitespace().collect::<Vec<_>>();
        let mut actual = structural.iter().copied().peekable();
        for (index, keyword) in expected.iter().enumerate() {
            if actual.next() != Some(*keyword) {
                return Err(SecretCommandError::Template);
            }
            let next_keyword = expected.get(index.saturating_add(1)).copied();
            if matches!(*keyword, "user" | "interface" | "peer" | "proxy")
                && actual.peek().copied() != next_keyword
            {
                let context = actual.next().ok_or(SecretCommandError::Template)?;
                if !context.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'-' | b'_' | b'.' | b'/' | b'+' | b'=')
                }) {
                    return Err(SecretCommandError::Template);
                }
            }
        }
        if actual.next().is_some() {
            return Err(SecretCommandError::Template);
        }
        Ok(Self {
            line: SecretString::from(template.to_owned()),
            validated,
            template: true,
        })
    }

    /// Returns catalog metadata without exposing secret values.
    #[inline]
    #[must_use]
    pub const fn validated(&self) -> &ValidatedRequest {
        &self.validated
    }

    /// Returns classified secret arguments for response and audit scrubbing.
    #[inline]
    #[must_use]
    pub const fn secrets(&self) -> &SecretValue {
        self.validated.protected_value()
    }

    /// Assembles the plaintext command only for immediate transmission.
    ///
    /// # Errors
    ///
    /// Returns a value-free error when a template slot cannot be encoded.
    #[inline]
    pub fn expose_for_send(&self) -> Result<Zeroizing<String>, SecretCommandError> {
        if self
            .line
            .expose_secret()
            .chars()
            .any(|character| character.is_control() && character != '\t')
        {
            return Err(QuoteError::ControlCharacter.into());
        }
        if !self.template {
            return Ok(Zeroizing::new(self.line.expose_secret().to_owned()));
        }
        let wire = self.validated.expose_for_send();
        let mut line = Zeroizing::new(String::new());
        for token in self.line.expose_secret().split_whitespace() {
            if !line.is_empty() {
                line.push(' ');
            }
            match token
                .strip_prefix('{')
                .and_then(|word| word.strip_suffix('}'))
            {
                Some(pointer) => {
                    let value = wire
                        .expose_secret()
                        .pointer(pointer)
                        .and_then(Value::as_str)
                        .ok_or(SecretCommandError::Template)?;
                    let quoted = quote_cli_word(value)?;
                    line.push_str(quoted.expose_secret());
                }
                None => line.push_str(token),
            }
        }
        Ok(line)
    }
}

impl fmt::Debug for CliCommand {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CliCommand")
            .field("line", &"<redacted>")
            .field("validated", &self.validated)
            .field("template", &self.template)
            .finish()
    }
}

impl PartialEq for CliCommand {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.validated == other.validated
            && self.template == other.template
            && self.line.expose_secret() == other.line.expose_secret()
    }
}

impl Serialize for CliCommand {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        json!({"line":"<redacted>", "validated":self.validated}).serialize(serializer)
    }
}
