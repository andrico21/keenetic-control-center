//! Secret-bearing CLI command ownership and structural argument binding.

use core::fmt;

use kcc_catalog::{SecretValue, ValidatedRequest};
use kcc_config::quoting::{QuoteError, quote_cli_word};
use secrecy::{ExposeSecret, SecretString};
use serde::{Serialize, Serializer};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::grammar::validate_grammar;

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
        if validated
            .protected_value()
            .secret_pointers()
            .any(|pointer| {
                template
                    .split_whitespace()
                    .filter(|token| *token == format!("{{{pointer}}}"))
                    .count()
                    != 1
            })
        {
            return Err(SecretCommandError::Template);
        }
        validate_grammar(&validated, template)?;
        let command = Self {
            line: SecretString::from(template.to_owned()),
            validated,
            template: true,
        };
        drop(command.expose_for_send()?);
        Ok(command)
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
        let mut words = Vec::new();
        for token in self.line.expose_secret().split_whitespace() {
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
                    words.push(quote_cli_word(value)?);
                }
                None => words.push(SecretString::from(token)),
            }
        }
        Ok(Zeroizing::new(
            words
                .iter()
                .map(ExposeSecret::expose_secret)
                .collect::<Vec<_>>()
                .join(" "),
        ))
    }
}

impl fmt::Debug for CliCommand {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            line: _,
            validated,
            template,
        } = self;
        f.debug_struct("CliCommand")
            .field("line", &"<redacted>")
            .field("validated", validated)
            .field("template", template)
            .finish()
    }
}

impl PartialEq for CliCommand {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        let Self {
            line,
            validated,
            template,
        } = self;
        let Self {
            line: other_line,
            validated: other_validated,
            template: other_template,
        } = other;
        validated == other_validated
            && template == other_template
            && line.expose_secret() == other_line.expose_secret()
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
