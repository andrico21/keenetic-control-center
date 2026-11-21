//! Token grammars: every argument of an [`EntwareCommand`](crate::command::EntwareCommand)
//! is one of these types, so no unchecked text reaches a command.

use russh::keys::{Algorithm, PublicKey};

use crate::error::{Grammar, SshError};

/// An opkg package name: `^[a-z0-9][a-z0-9+._-]{0,63}$`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub struct PackageName(String);

impl PackageName {
    /// Parses `text`.
    ///
    /// # Errors
    ///
    /// Returns [`SshError::InvalidArgument`] for text outside the grammar.
    #[inline]
    pub fn parse(text: &str) -> Result<Self, SshError> {
        is_package_name(text)
            .then(|| Self(text.to_owned()))
            .ok_or(SshError::InvalidArgument(Grammar::PackageName))
    }

    /// The name.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An init script file name in `/opt/etc/init.d`: `^S[0-9]{2}[A-Za-z0-9._-]{1,48}$`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub struct ServiceName(String);

impl ServiceName {
    /// Parses `text`.
    ///
    /// # Errors
    ///
    /// Returns [`SshError::InvalidArgument`] for text outside the grammar.
    #[inline]
    pub fn parse(text: &str) -> Result<Self, SshError> {
        is_service_name(text)
            .then(|| Self(text.to_owned()))
            .ok_or(SshError::InvalidArgument(Grammar::ServiceName))
    }

    /// The file name.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A kcc router id: 1 to 32 of `[a-z0-9-]`, the rule of `kcc.toml` router profiles.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub struct RouterId(String);

impl RouterId {
    /// Parses `text`.
    ///
    /// # Errors
    ///
    /// Returns [`SshError::InvalidArgument`] for text outside the rule.
    #[inline]
    pub fn parse(text: &str) -> Result<Self, SshError> {
        is_router_id(text)
            .then(|| Self(text.to_owned()))
            .ok_or(SshError::InvalidArgument(Grammar::RouterId))
    }

    /// The id.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An `authorized_keys` key without comment: `ssh-ed25519 <base64>` whose base64 decodes
/// to an ed25519 public key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct PublicKeyLine(String);

impl PublicKeyLine {
    /// Parses `text`.
    ///
    /// # Errors
    ///
    /// Returns [`SshError::InvalidArgument`] for any other text.
    #[inline]
    pub fn parse(text: &str) -> Result<Self, SshError> {
        is_public_key_line(text)
            .then(|| Self(text.to_owned()))
            .ok_or(SshError::InvalidArgument(Grammar::PublicKeyLine))
    }

    /// The line.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An `rc.func` action kcc sends.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ServiceAction {
    /// `start`.
    Start,
    /// `stop`.
    Stop,
    /// `restart`.
    Restart,
    /// `check`: reads the state.
    Check,
}

impl ServiceAction {
    /// The word passed to the init script.
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Check => "check",
        }
    }
}

/// Whether `text` matches `^[a-z0-9][a-z0-9+._-]{0,63}$`.
fn is_package_name(text: &str) -> bool {
    let [first, rest @ ..] = text.as_bytes() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && rest.len() <= 63
        && rest.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+._-".contains(byte)
        })
}

/// Whether `text` matches `^S[0-9]{2}[A-Za-z0-9._-]{1,48}$`.
fn is_service_name(text: &str) -> bool {
    let [b'S', tens, ones, rest @ ..] = text.as_bytes() else {
        return false;
    };
    tens.is_ascii_digit()
        && ones.is_ascii_digit()
        && (1..=48).contains(&rest.len())
        && rest
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(byte))
}

/// Whether `text` is 1 to 32 of `[a-z0-9-]`.
fn is_router_id(text: &str) -> bool {
    (1..=32).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Whether `text` is `ssh-ed25519 <base64>` and decodes to an ed25519 key.
fn is_public_key_line(text: &str) -> bool {
    text.strip_prefix("ssh-ed25519 ").is_some_and(|encoded| {
        !encoded.is_empty()
            && encoded
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte))
    }) && PublicKey::from_openssh(text).is_ok_and(|key| key.algorithm() == Algorithm::Ed25519)
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests;
