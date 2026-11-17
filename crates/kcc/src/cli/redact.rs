//! Configuration text without its secrets, as the Web UI's redacted download.

use kcc_config::{
    config_text::{flatten, parse},
    mask,
};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};

use super::exit::{Exit, Failure, Outcome};

/// `text` with every registered secret and every `ns3` blob replaced, marked as redacted
/// and without the router checksum that no longer matches it.
///
/// # Errors
///
/// Returns a validation failure when `text` is not a configuration.
pub(crate) fn redacted_copy(text: &str) -> Outcome<String> {
    mask::redacted_copy(text).map_err(|error| Failure::text(Exit::Validation, &error))
}

/// The flattened commands of one configuration: a digest of each complete command and the
/// same command with its secrets replaced, in order.
pub(crate) struct Lines {
    /// SHA-256 of each command's complete text, secrets included.
    digests: Vec<[u8; 32]>,
    /// Each command with its secrets replaced.
    shown: Vec<String>,
}

impl Lines {
    /// The commands of `text`.
    ///
    /// # Errors
    ///
    /// Returns a validation failure when `text` is not a configuration.
    pub(crate) fn read(text: &str) -> Outcome<Self> {
        let ast = parse(text).map_err(|error| Failure::text(Exit::Validation, &error))?;
        let digests = flatten(&ast)
            .iter()
            .map(|line| {
                let complete = SecretString::from(line.to_string());
                Sha256::digest(complete.expose_secret().as_bytes()).into()
            })
            .collect();
        let shown = flatten(&mask::redacted_config(&ast))
            .iter()
            .map(ToString::to_string)
            .collect();
        Ok(Self { digests, shown })
    }

    /// The digest of each command, in order.
    pub(crate) fn digests(&self) -> &[[u8; 32]] {
        &self.digests
    }

    /// Command `index` with its secrets replaced.
    pub(crate) fn shown(&self, index: usize) -> &str {
        self.shown.get(index).map_or("", String::as_str)
    }
}
