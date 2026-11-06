//! Management classification and deterministic plan identities.

use alloc::collections::BTreeSet;
use core::fmt::Write as _;

use md5::{Digest as _, Md5};

use super::{ConfigFingerprint, PlanPhases};

/// Identifies commands that can cut off the current management connection.
pub(super) fn is_management_line(line: &str, management_interface: Option<&str>) -> bool {
    let words = line.split_whitespace().collect::<Vec<_>>();
    match words.as_slice() {
        ["user", _name, "password", "plain", ..] => true,
        ["ip", "http", "port" | "ssl", ..] => true,
        ["interface", interface, rest @ ..] => management_interface.is_some_and(|current| {
            current == *interface
                && matches!(
                    rest,
                    ["ip", "address" | "security-level", ..] | ["security-level", ..]
                )
        }),
        _ => false,
    }
}

/// Computes a lowercase MD5 string.
pub(super) fn digest_text(text: &str) -> String {
    hex_digest(Md5::digest(text.as_bytes()).as_slice())
}

/// Hashes a normalized set with unambiguous line separators.
pub(super) fn digest_lines(lines: &BTreeSet<String>) -> String {
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
pub(super) fn plan_id(
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
