//! Every workspace member must inherit the lint profile with `[lints] workspace = true`.
//!
//! Cargo's `missing_lints_inheritance` is satisfied by an empty `[lints]` table, so it
//! does not prove that a member inherits the profile (guidelines Section 9).

use std::{
    fs,
    path::{Path, PathBuf},
};

use toml::{Table, Value};

use crate::{failure::GateError, manifest};

/// Names every member of the root workspace whose manifest lacks `[lints] workspace = true`.
///
/// Member patterns are plain paths or `dir/*`; `[workspace] exclude` entries are skipped.
///
/// # Errors
///
/// Returns a [`GateError`] when the root manifest has no `[workspace]` table, a pattern
/// uses another glob form, or a member directory or manifest cannot be read.
pub(crate) fn violations(root: &Path, root_doc: &Table) -> Result<Vec<String>, GateError> {
    let root_path = root.join("Cargo.toml");
    let workspace = manifest::table_at(root_doc, &["workspace"], &root_path)?;
    let excluded = strings(workspace.get("exclude"));
    let mut found = Vec::new();
    for pattern in strings(workspace.get("members")) {
        for member in expand(root, &pattern)? {
            let relative = member.strip_prefix(root).unwrap_or(&member).to_path_buf();
            if excluded.iter().any(|skip| relative == Path::new(skip)) {
                continue;
            }
            let path = member.join("Cargo.toml");
            let doc = manifest::read(&path)?;
            let inherits = doc
                .get("lints")
                .and_then(|lints| lints.get("workspace"))
                .and_then(Value::as_bool)
                == Some(true);
            if !inherits {
                found.push(format!(
                    "{}: [lints] lacks workspace = true",
                    relative.join("Cargo.toml").display()
                ));
            }
        }
    }
    found.sort();
    Ok(found)
}

/// The string entries of an optional TOML array.
fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// Expands one member pattern into member directories.
///
/// # Errors
///
/// Returns [`GateError::Command`] for a glob other than a trailing `/*`, and
/// [`GateError::Read`] when the parent directory cannot be listed.
fn expand(root: &Path, pattern: &str) -> Result<Vec<PathBuf>, GateError> {
    let Some(parent) = pattern.strip_suffix("/*") else {
        if pattern.contains(['*', '?', '[']) {
            return Err(GateError::Command {
                program: "profile-eq".to_owned(),
                detail: format!("unsupported workspace member pattern {pattern:?}"),
            });
        }
        return Ok(vec![root.join(pattern)]);
    };
    let dir = root.join(parent);
    let read_error = |source| GateError::Read {
        path: dir.clone(),
        source,
    };
    let mut members = Vec::new();
    for entry in fs::read_dir(&dir).map_err(read_error)? {
        let path = entry.map_err(read_error)?.path();
        if path.is_dir() {
            members.push(path);
        }
    }
    members.sort();
    Ok(members)
}
