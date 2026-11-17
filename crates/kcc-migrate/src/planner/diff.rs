//! Management classification and deterministic plan identities.

use alloc::collections::BTreeSet;
use core::fmt::Write as _;

use kcc_config::config_text::{Token, flatten, parse};
use md5::{Digest as _, Md5};
use secrecy::SecretString;

use super::{ConfigFingerprint, PlanPhases};
use crate::management;

/// How a command touches the password of the router account kcc signs in with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoginPassword {
    /// The command leaves the login's password alone.
    Untouched,
    /// The command sets a new password (`plain`, `md5` or `nt`).
    Set,
    /// The command removes the password (`no user <login> password ...`).
    Removed,
}

impl LoginPassword {
    /// Classifies `line` for the account `login`.
    pub(crate) fn of(line: &str, login: &str) -> Self {
        let words = line.split_whitespace().collect::<Vec<_>>();
        match words.as_slice() {
            ["user", name, "password", "plain" | "md5" | "nt", ..] if *name == login => Self::Set,
            ["no", "user", name, "password", ..] if *name == login => Self::Removed,
            _ => Self::Untouched,
        }
    }
}

/// The password a `user <login> password plain <secret>` line sets, read as configuration
/// text so a quoted secret is unquoted.
pub(crate) fn plain_password(line: &str, login: &str) -> Option<SecretString> {
    let parsed = parse(line).ok()?;
    let commands = flatten(&parsed);
    let [command] = commands.as_slice() else {
        return None;
    };
    match command.tokens.as_slice() {
        [
            Token::Word(user),
            Token::Word(name),
            Token::Word(password),
            Token::Word(kind),
            Token::Word(secret),
        ] if user == "user" && name == login && password == "password" && kind == "plain" => {
            Some(SecretString::from(secret.clone()))
        }
        _ => None,
    }
}

/// Identifies commands that can cut off the current management connection of `login`.
pub(crate) fn is_management_line(
    line: &str,
    management_interface: Option<&str>,
    login: &str,
) -> bool {
    if LoginPassword::of(line, login) != LoginPassword::Untouched {
        return true;
    }
    let words = line.split_whitespace().collect::<Vec<_>>();
    match words.as_slice() {
        ["user", _name, "password", "plain", ..] => true,
        ["ip", "http", "port" | "ssl", ..] => true,
        ["interface", interface, rest @ ..] => {
            matches!(
                rest,
                ["ip", "address" | "security-level", ..] | ["security-level", ..]
            ) && management::may_carry(management_interface, interface)
        }
        _ => false,
    }
}

/// Computes a lowercase MD5 string.
pub(crate) fn digest_text(text: &str) -> String {
    hex_digest(Md5::digest(text.as_bytes()).as_slice())
}

/// Hashes a normalized set with unambiguous line separators.
pub(crate) fn digest_lines(lines: &BTreeSet<String>) -> String {
    let mut digest = Md5::new();
    for (index, line) in lines.iter().enumerate() {
        if index != 0 {
            digest.update(b"\n");
        }
        digest.update(line.as_bytes());
    }
    hex_digest(digest.finalize().as_slice())
}

/// Derives the identity without assembling another plaintext copy of the commands.
pub(crate) fn plan_id(
    source: &ConfigFingerprint,
    target: &ConfigFingerprint,
    phases: &PlanPhases,
) -> String {
    let mut digest = Md5::new();
    for fingerprint in [
        &source.startup_md5,
        &source.last_change_checksum,
        &target.startup_md5,
        &target.last_change_checksum,
    ] {
        digest.update(fingerprint.as_bytes());
        digest.update(b"\n");
    }
    for (index, line) in phases
        .additive
        .iter()
        .chain(&phases.prune)
        .chain(&phases.management)
        .enumerate()
    {
        if index != 0 {
            digest.update(b"\n");
        }
        digest.update(line.expose_command().as_bytes());
    }
    hex_digest(digest.finalize().as_slice())
}

/// Formats digest bytes; formatting into an owned string cannot fail.
fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(32);
    for byte in bytes {
        let _result = write!(output, "{byte:02x}");
    }
    output
}
