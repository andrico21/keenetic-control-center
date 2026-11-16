//! The audit files, their one line reader, and the hash chain rule.

extern crate alloc;

use alloc::collections::BTreeMap;
use std::{
    fs::{self, File},
    io::{BufRead as _, BufReader},
    path::{Path, PathBuf},
};

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::{AUDIT_FILE_NAME, AuditEntry, AuditError, GENESIS_HASH, json_error};
use crate::persist::io_error;

/// What [`entries`] checks besides parsing each line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Check {
    /// Every entry links to the one before it and carries its own hash.
    Chain,
    /// Nothing: for showing a log whose chain does not verify.
    Parse,
}

/// Reads the entries of every archive and the active file, in chain order.
///
/// An unterminated last line of the active file is skipped: it is crash debris or
/// another process's append in progress, not an entry. Elsewhere every line counts.
///
/// # Errors
///
/// Returns the first I/O or JSON error, or with [`Check::Chain`] the first invalid
/// sequence in [`AuditError::Chain`].
pub(super) fn entries(dir: &Path, check: Check) -> Result<Vec<AuditEntry>, AuditError> {
    let mut entries = Vec::new();
    let mut paths = rotated_files(dir)?;
    let active = dir.join(AUDIT_FILE_NAME);
    let rotated = paths.len();
    if active.exists() {
        paths.push(active);
    }
    for (index, path) in paths.iter().enumerate() {
        let rest = for_each_line(path, |line| accept(&mut entries, check, line))?;
        if let Some(line) = rest
            && index < rotated
        {
            accept(&mut entries, check, &line)?;
        }
    }
    Ok(entries)
}

/// Parses `line` and, with [`Check::Chain`], checks it against the entry before it.
///
/// # Errors
///
/// As [`entries`].
fn accept(entries: &mut Vec<AuditEntry>, check: Check, line: &[u8]) -> Result<(), AuditError> {
    let entry: AuditEntry = serde_json::from_slice(line).map_err(|error| json_error(&error))?;
    if check == Check::Chain {
        let unlinked = entries.last().is_some_and(|previous| {
            entry.seq != previous.seq.saturating_add(1) || entry.prev_hash != previous.hash
        });
        let forged_genesis =
            entries.is_empty() && entry.seq == 1 && entry.prev_hash != GENESIS_HASH;
        if unlinked || forged_genesis || calculate_hash(&entry)? != entry.hash {
            return Err(AuditError::Chain { seq: entry.seq });
        }
    }
    entries.push(entry);
    Ok(())
}

/// Calls `each` with every non-empty `\n`-terminated line of `path`, without its `\n`,
/// and returns the unterminated rest of the file, if any.
///
/// # Errors
///
/// Returns an I/O error, or the first error of `each`.
fn for_each_line(
    path: &Path,
    mut each: impl FnMut(&[u8]) -> Result<(), AuditError>,
) -> Result<Option<Vec<u8>>, AuditError> {
    let file = File::open(path).map_err(|error| io_error(path, error))?;
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = reader
            .read_until(b'\n', &mut line)
            .map_err(|error| io_error(path, error))?;
        if read == 0 {
            return Ok(None);
        }
        let Some(body) = line.strip_suffix(b"\n") else {
            return Ok(Some(line));
        };
        if !body.is_empty() {
            each(body)?;
        }
    }
}

/// Discovers rotated audit files in sequence order.
///
/// # Errors
///
/// Returns an I/O error when the audit directory cannot be listed.
pub(super) fn rotated_files(dir: &Path) -> Result<Vec<PathBuf>, AuditError> {
    let mut rotated = Vec::new();
    for listed in fs::read_dir(dir).map_err(|error| io_error(dir, error))? {
        let entry = listed.map_err(|error| io_error(dir, error))?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if name.starts_with("audit-")
            && Path::new(name)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("jsonl"))
        {
            rotated.push(entry.path());
        }
    }
    rotated.sort();
    Ok(rotated)
}

/// Calculates `sha256(prev_hash || canonical_json(entry_without_hash))`.
///
/// # Errors
///
/// Returns a canonical serialization or hash encoding error.
pub(super) fn calculate_hash(entry: &AuditEntry) -> Result<String, AuditError> {
    let canonical = canonical_entry_without_hash(entry)?;
    let mut digest = Sha256::new();
    digest.update(entry.prev_hash.as_bytes());
    digest.update(canonical);
    let bytes = digest.finalize();
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use core::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_error| AuditError::Json {
            reason: "hash encoding failed".to_owned(),
        })?;
    }
    Ok(encoded)
}

/// Serializes a fixed-order map so hash bytes are stable across processes.
///
/// # Errors
///
/// Returns an error if one of the entry fields cannot be serialized.
fn canonical_entry_without_hash(entry: &AuditEntry) -> Result<Vec<u8>, AuditError> {
    let mut fields = BTreeMap::new();
    drop(fields.insert(
        "action",
        serde_json::to_value(&entry.action).map_err(|error| json_error(&error))?,
    ));
    drop(fields.insert(
        "actor",
        serde_json::to_value(&entry.actor).map_err(|error| json_error(&error))?,
    ));
    drop(fields.insert(
        "outcome",
        serde_json::to_value(&entry.outcome).map_err(|error| json_error(&error))?,
    ));
    drop(fields.insert("params_redacted", entry.params_redacted.clone()));
    drop(fields.insert("prev_hash", Value::from(entry.prev_hash.clone())));
    drop(fields.insert("request_id", Value::from(entry.request_id.clone())));
    drop(fields.insert(
        "router",
        serde_json::to_value(&entry.router).map_err(|error| json_error(&error))?,
    ));
    drop(fields.insert("seq", Value::from(entry.seq)));
    drop(fields.insert(
        "target",
        serde_json::to_value(&entry.target).map_err(|error| json_error(&error))?,
    ));
    drop(fields.insert("ts", Value::from(entry.ts)));
    serde_json::to_vec(&fields).map_err(|error| json_error(&error))
}
