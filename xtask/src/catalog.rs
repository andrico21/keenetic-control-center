//! Shared catalog types: the model list, manual URLs, the cache layout and `sources.lock`.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::failure::GateError;

/// Base URL of the published CLI manuals.
const URL_BASE: &str = "https://storage.googleapis.com/docs.help.keenetic.com/cli";

/// Builds the manual URL for a firmware `version` and a model id such as `KN-1811`.
pub(crate) fn manual_url(version: &str, model: &str) -> String {
    format!(
        "{URL_BASE}/{version}/en/cli_manual_{}.pdf",
        model.to_lowercase()
    )
}

/// `<root>/catalog`.
fn catalog_dir(root: &Path) -> PathBuf {
    root.join("catalog")
}

/// `<root>/catalog/.cache`, gitignored.
pub(crate) fn cache_dir(root: &Path) -> PathBuf {
    catalog_dir(root).join(".cache")
}

/// `<root>/catalog/sources.toml`.
pub(crate) fn sources_path(root: &Path) -> PathBuf {
    catalog_dir(root).join("sources.toml")
}

/// `<root>/catalog/sources.lock`.
pub(crate) fn lock_path(root: &Path) -> PathBuf {
    catalog_dir(root).join("sources.lock")
}

/// The model list file: Keenetic ids plus Netcraze ids to probe.
#[derive(Debug, Deserialize)]
struct Sources {
    /// Keenetic model ids.
    models: Vec<String>,
    /// Netcraze model ids.
    #[serde(default)]
    netcraze: Vec<String>,
}

/// Reads a model list file and returns every model id in file order.
///
/// # Errors
///
/// Returns [`GateError::Read`] or [`GateError::Toml`].
pub(crate) fn read_models(path: &Path) -> Result<Vec<String>, GateError> {
    let text = fs::read_to_string(path).map_err(|source| GateError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let sources: Sources = toml::from_str(&text).map_err(|source| GateError::Toml {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(sources.models.into_iter().chain(sources.netcraze).collect())
}

/// One fetched (or absent) manual.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Entry {
    /// Firmware version, for example `5.1`.
    pub version: String,
    /// Model id, for example `KN-1811`.
    pub model: String,
    /// The URL that was requested.
    pub url: String,
    /// The HTTP status of the answer.
    pub status: u16,
    /// True when the server has no manual for this model and version.
    pub absent: bool,
    /// Hex SHA-256 of the PDF, present for a 200.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// PDF size in bytes, present for a 200.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// UTC date of the fetch, `YYYY-MM-DD`.
    pub fetch_date: String,
}

/// How the last `extract` produced the text files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Extraction {
    /// `native` (local `pdftotext`) or `podman` (Debian container).
    pub method: String,
    /// The poppler version string.
    pub poppler: String,
    /// UTC date of the extraction, `YYYY-MM-DD`.
    pub date: String,
}

/// The contents of `catalog/sources.lock`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Lock {
    /// The last text extraction, if one ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extraction: Option<Extraction>,
    /// Every recorded manual, sorted by version then model.
    #[serde(default)]
    pub entries: Vec<Entry>,
}

impl Lock {
    /// Reads the lock file; a missing file is an empty lock.
    ///
    /// # Errors
    ///
    /// Returns [`GateError::Read`] or [`GateError::Toml`].
    pub(crate) fn load(path: &Path) -> Result<Self, GateError> {
        match fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|source| GateError::Toml {
                path: path.to_path_buf(),
                source,
            }),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(GateError::Read {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Writes the lock file.
    ///
    /// # Errors
    ///
    /// Returns [`GateError::Write`].
    pub(crate) fn save(&self, path: &Path) -> Result<(), GateError> {
        let text = self.to_toml().map_err(|detail| GateError::Write {
            path: path.to_path_buf(),
            detail,
        })?;
        fs::write(path, text).map_err(|source| GateError::Write {
            path: path.to_path_buf(),
            detail: source.to_string(),
        })
    }

    /// Serialises the lock as TOML.
    ///
    /// # Errors
    ///
    /// Returns the serialiser's message.
    pub(crate) fn to_toml(&self) -> Result<String, String> {
        toml::to_string(self).map_err(|source| source.to_string())
    }

    /// Inserts `entry`, replacing any entry for the same version and model, and keeps
    /// the entries sorted.
    pub(crate) fn upsert(&mut self, entry: Entry) {
        self.entries
            .retain(|old| old.version != entry.version || old.model != entry.model);
        self.entries.push(entry);
        self.entries.sort_by(|left, right| {
            (&left.version, &left.model).cmp(&(&right.version, &right.model))
        });
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use super::{Entry, Extraction, Lock, manual_url};

    fn entry(version: &str, model: &str, status: u16) -> Entry {
        let found = status == 200;
        Entry {
            version: version.to_owned(),
            model: model.to_owned(),
            url: manual_url(version, model),
            status,
            absent: !found,
            sha256: found.then(|| "ab".repeat(32)),
            size: found.then_some(1234),
            fetch_date: "2026-11-05".to_owned(),
        }
    }

    #[test]
    fn url_is_built_from_lowercase_model() {
        assert_eq!(
            manual_url("5.1", "KN-1811"),
            "https://storage.googleapis.com/docs.help.keenetic.com/cli/5.1/en/cli_manual_kn-1811.pdf",
            "Keenetic URL"
        );
        assert_eq!(
            manual_url("4.3", "NC-1812"),
            "https://storage.googleapis.com/docs.help.keenetic.com/cli/4.3/en/cli_manual_nc-1812.pdf",
            "Netcraze URL"
        );
    }

    #[test]
    fn lock_round_trips_through_toml() -> Result<(), Box<dyn Error>> {
        let mut lock = Lock::default();
        lock.upsert(entry("5.1", "KN-1811", 200));
        lock.upsert(entry("4.3", "KN-1811", 200));
        lock.upsert(entry("9.9", "KN-1811", 404));
        lock.extraction = Some(Extraction {
            method: "podman".to_owned(),
            poppler: "22.12.0-2+deb12u1".to_owned(),
            date: "2026-11-05".to_owned(),
        });
        let text = lock.to_toml()?;
        let back: Lock = toml::from_str(&text)?;
        assert_eq!(back, lock, "round trip");
        let versions: Vec<_> = back
            .entries
            .iter()
            .map(|item| item.version.as_str())
            .collect();
        assert_eq!(versions, ["4.3", "5.1", "9.9"], "sorted by version");
        Ok(())
    }

    #[test]
    fn upsert_replaces_the_same_model_and_version() {
        let mut lock = Lock::default();
        lock.upsert(entry("5.1", "KN-1811", 404));
        lock.upsert(entry("5.1", "KN-1811", 200));
        assert_eq!(lock.entries.len(), 1, "one entry");
        assert_eq!(
            lock.entries.first().map(|item| item.status),
            Some(200),
            "newest wins"
        );
    }
}
