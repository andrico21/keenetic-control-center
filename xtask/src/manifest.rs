//! Reading Cargo manifests and their lint tables.

use std::{fs, path::Path};

use toml::Table;

use crate::failure::GateError;

/// Key path of the lint tables in the root workspace manifest.
pub(crate) const WORKSPACE_LINTS: [&str; 2] = ["workspace", "lints"];

/// Key path of the lint tables in a package manifest.
pub(crate) const PACKAGE_LINTS: [&str; 1] = ["lints"];

/// Reads and parses a TOML manifest.
///
/// # Errors
///
/// Returns [`GateError::Read`] or [`GateError::Toml`].
pub(crate) fn read(path: &Path) -> Result<Table, GateError> {
    let text = fs::read_to_string(path).map_err(|source| GateError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    text.parse::<Table>().map_err(|source| GateError::Toml {
        path: path.to_path_buf(),
        source,
    })
}

/// Follows `keys` from the document root to a nested table.
///
/// # Errors
///
/// Returns [`GateError::MissingTable`] when a key is absent or not a table.
pub(crate) fn table_at<'doc>(
    doc: &'doc Table,
    keys: &[&str],
    path: &Path,
) -> Result<&'doc Table, GateError> {
    keys.iter().try_fold(doc, |table, key| {
        table
            .get(*key)
            .and_then(toml::Value::as_table)
            .ok_or_else(|| GateError::MissingTable {
                path: path.to_path_buf(),
                key: keys.join("."),
            })
    })
}
