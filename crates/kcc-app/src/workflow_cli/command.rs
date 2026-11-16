//! Secret-bearing CLI command ownership and structural argument binding.

use core::fmt;

use kcc_catalog::{SecretValue, ValidatedRequest};
use kcc_config::{
    config_text::{Token, flatten, parse},
    ns3,
    quoting::{QuoteError, quote_cli_word},
};
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
    /// The line does not render the request it is paired with.
    #[error("CLI line does not render the validated command")]
    Line,
}

impl CliCommand {
    /// Binds a literal line to the request it renders, moving it into zeroizing storage.
    ///
    /// The line must render the request (see [`ValidatedRequest::renders_cli`]): one
    /// command of the request's own path, read as the router reads it (quoted words
    /// unquoted), whose arguments are exactly the validated ones. A raw request outside
    /// the catalog takes only the line it was authorized as.
    ///
    /// # Errors
    ///
    /// Returns [`SecretCommandError::Line`] when the line does not render the request.
    #[inline]
    pub fn new(line: String, validated: ValidatedRequest) -> Result<Self, SecretCommandError> {
        bind(&line, &validated)?;
        Ok(Self {
            line: SecretString::from(line),
            validated,
            template: false,
        })
    }

    /// Owns an explicitly secret line bound like [`Self::new`]; its printable
    /// representations are always redacted. `ns3` words are read decoded.
    ///
    /// # Errors
    ///
    /// Returns [`SecretCommandError::Line`] when the line does not render the request.
    #[inline]
    pub fn secret(
        mut structural: ValidatedRequest,
        line: SecretString,
    ) -> Result<Self, SecretCommandError> {
        bind(line.expose_secret(), &structural)?;
        structural.protected.retain_scrubber(line.clone());
        Ok(Self {
            line,
            validated: structural,
            template: false,
        })
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

/// Refuses a line that does not render `validated`.
///
/// # Errors
///
/// Returns [`SecretCommandError::Line`] for an unparseable line or one that renders
/// another request.
fn bind(line: &str, validated: &ValidatedRequest) -> Result<(), SecretCommandError> {
    let owned = words(line).ok_or(SecretCommandError::Line)?;
    let exposed = owned
        .iter()
        .map(ExposeSecret::expose_secret)
        .collect::<Vec<_>>();
    validated
        .renders_cli(&exposed)
        .then_some(())
        .ok_or(SecretCommandError::Line)
}

/// The words of one CLI line as the router's configuration parser reads them: quoted
/// words unquoted, `ns3` words decoded. `None` for anything but exactly one line.
fn words(line: &str) -> Option<Vec<SecretString>> {
    if line.contains(['\n', '\r']) {
        return None;
    }
    let ast = parse(line).ok()?;
    let [command] = <[_; 1]>::try_from(flatten(&ast)).ok()?;
    command
        .tokens
        .into_iter()
        .map(|token| match token {
            Token::Word(word) => Some(SecretString::from(word)),
            Token::Ns3(blob) => ns3::decode(&blob).ok(),
            _ => None,
        })
        .collect()
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
