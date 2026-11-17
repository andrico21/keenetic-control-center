//! The wizards' files under `<state>/migrations/<id>/`.
//!
//! - the record, named by its wizard ([`Flow::FILE`]: `wizard.json` for a migration,
//!   `preset.json` for a preset run), which never holds a secret.
//! - `source.sealed` and `passwords.sealed`: the source configuration and the typed
//!   passwords, sealed with the backup key (XChaCha20-Poly1305, the backups' scheme) under
//!   the bindings `migration:<id>:source` and `migration:<id>:passwords`, so neither
//!   opens as a backup nor a backup as one of them.
//! - `report.json`: the redacted report of the reviewed plan.
//!
//! Beside the runs, each wizard keeps an index of its runs' owners (see
//! [`super::index`]).
//!
//! On unix the directories are `0700` and the files `0600`; every file is written to a
//! temporary name, synced and renamed into place.
//!
//! Each wizard reads only records under its own file name, so neither opens the other's
//! runs; a preset run seals a copied (transient) preset as [`Sealed::Preset`].

use std::{io, path::Path};

use kcc_app::secrets::{CryptoError, MasterKey, binding::Binding};
use secrecy::SecretString;
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

use self::files::Files;
use super::{flow::Flow, index};
use crate::blocking;

pub(super) mod files;

/// A sealed part of a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sealed {
    /// The source startup configuration.
    Source,
    /// The typed passwords, as a JSON object of user names.
    Passwords,
    /// A copy run's transient preset: the copied settings, never stored as a preset.
    Preset,
}

impl Sealed {
    /// The part's file name.
    const fn file(self) -> &'static str {
        match self {
            Self::Source => "source.sealed",
            Self::Passwords => "passwords.sealed",
            Self::Preset => "preset.sealed",
        }
    }

    /// The binding the part of run `id` is sealed under.
    fn binding(self, id: &str) -> Binding {
        match self {
            Self::Source => Binding::migration_source(id),
            Self::Passwords => Binding::migration_passwords(id),
            Self::Preset => Binding::preset_run(id),
        }
    }
}

/// A redacted file kept from the apply on, when the plan can no longer be built again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kept {
    /// The report of the applied plan, as JSON.
    Report,
    /// The applied plan's redacted form.
    Plan,
}

impl Kept {
    /// The file's name.
    const fn file(self) -> &'static str {
        match self {
            Self::Report => "report.json",
            Self::Plan => "plan.json",
        }
    }
}

/// Why a migration's files could not be used.
#[derive(Debug, Error)]
pub(crate) enum StoreError {
    /// A file or directory could not be read or written.
    #[error("migration state I/O failed: {0}")]
    Io(#[from] io::Error),
    /// A file is not in the expected format.
    #[error("migration state is malformed")]
    Malformed,
    /// A sealed part could not be sealed or opened.
    #[error("migration state could not be sealed or opened: {0}")]
    Crypto(#[from] CryptoError),
}

/// The migrations directory of one state directory.
///
/// Every method does its file work (reads, writes with fsync, sealing) on the blocking
/// pool; a method that writes still completes its write when the caller is dropped, and a
/// read is simply abandoned.
#[derive(Debug, Clone)]
pub(crate) struct Store {
    /// The files, used on the blocking pool only.
    files: Files,
}

impl Store {
    /// The migrations directory below `state_dir`.
    pub(crate) fn new(state_dir: &Path) -> Self {
        Self {
            files: Files::new(state_dir),
        }
    }

    /// Runs `work` over the files on the blocking pool.
    ///
    /// # Errors
    ///
    /// Returns the error of `work`, or an I/O error when the task did not finish.
    // NOT cancel-safe: dropped, `work` still runs to its end on the blocking pool.
    pub(crate) async fn run<T, W>(&self, work: W) -> Result<T, StoreError>
    where
        W: FnOnce(&Files) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        let files = self.files.clone();
        blocking::run(move || work(&files), StoreError::Io).await
    }

    /// The record `id`, when it exists and is in the current format.
    ///
    /// # Errors
    ///
    /// Returns read failures and malformed records.
    // cancel-safe: reads only.
    pub(crate) async fn load<F>(&self, id: &str) -> Result<Option<F>, StoreError>
    where
        F: Flow,
    {
        let run = id.to_owned();
        self.run(move |files| files.load::<F>(&run)).await
    }

    /// Writes `record`, creating its directory.
    ///
    /// # Errors
    ///
    /// Returns write failures.
    // NOT cancel-safe: dropped, the index entry and the record are still written.
    pub(crate) async fn save<F>(&self, record: &F) -> Result<(), StoreError>
    where
        F: Flow,
    {
        let bytes = json(record)?;
        let (run, user) = (record.id().to_owned(), record.owner().to_owned());
        self.run(move |files| {
            index::enter::<F>(files, &run, &user)?;
            files.write(&run, F::FILE, &bytes)
        })
        .await
    }

    /// Every readable record of `owner`, newest first: only the runs the index names
    /// for `owner` are read, and names whose record is gone are dropped from the index.
    ///
    /// # Errors
    ///
    /// Returns read failures of the index.
    // NOT cancel-safe: dropped, the index is still corrected.
    pub(crate) async fn list<F>(&self, owner: &str) -> Result<Vec<F>, StoreError>
    where
        F: Flow,
    {
        let user = owner.to_owned();
        self.run(move |files| files.list::<F>(&user)).await
    }

    /// Seals `text` as `part` of migration `id` with `key`.
    ///
    /// # Errors
    ///
    /// Returns sealing and write failures.
    // NOT cancel-safe: dropped, the sealed part is still written.
    pub(crate) async fn seal(
        &self,
        key: &MasterKey,
        id: &str,
        part: Sealed,
        text: &SecretString,
    ) -> Result<(), StoreError> {
        let (sealing, run, secret) = (key.duplicate(), id.to_owned(), text.clone());
        self.run(move |files| files.seal(&sealing, &run, part, &secret))
            .await
    }

    /// Opens `part` of migration `id` with `key`, when it was sealed.
    ///
    /// # Errors
    ///
    /// Returns read, format and opening failures.
    // cancel-safe: reads only.
    pub(crate) async fn open(
        &self,
        key: &MasterKey,
        id: &str,
        part: Sealed,
    ) -> Result<Option<SecretString>, StoreError> {
        let (opening, run) = (key.duplicate(), id.to_owned());
        self.run(move |files| files.open(&opening, &run, part))
            .await
    }

    /// Writes `value` as JSON to `file` of run `id`, creating its directory.
    ///
    /// # Errors
    ///
    /// Returns serialization and write failures.
    // NOT cancel-safe: dropped, the file is still written.
    pub(crate) async fn save_named<T>(
        &self,
        id: &str,
        file: &'static str,
        value: &T,
    ) -> Result<(), StoreError>
    where
        T: Serialize + Sync,
    {
        let (bytes, run) = (json(value)?, id.to_owned());
        self.run(move |files| files.write(&run, file, &bytes)).await
    }

    /// The JSON `file` of run `id`, when it exists.
    ///
    /// # Errors
    ///
    /// Returns read failures and a file that does not parse as `T`.
    // cancel-safe: reads only.
    pub(crate) async fn load_named<T>(
        &self,
        id: &str,
        file: &'static str,
    ) -> Result<Option<T>, StoreError>
    where
        T: DeserializeOwned + Send + 'static,
    {
        let run = id.to_owned();
        self.run(move |files| files.load_named::<T>(&run, file))
            .await
    }

    /// Deletes `part` of run `id`, when it was sealed.
    ///
    /// # Errors
    ///
    /// Returns removal failures other than a missing file.
    // NOT cancel-safe: dropped, the part is still deleted.
    pub(crate) async fn discard(&self, id: &str, part: Sealed) -> Result<(), StoreError> {
        let run = id.to_owned();
        self.run(move |files| files.discard(&run, part)).await
    }

    /// Keeps the redacted `text` as `file` of migration `id`.
    ///
    /// # Errors
    ///
    /// Returns write failures.
    // NOT cancel-safe: dropped, the file is still written.
    pub(crate) async fn keep(&self, id: &str, file: Kept, text: &str) -> Result<(), StoreError> {
        let (run, redacted) = (id.to_owned(), text.to_owned());
        self.run(move |files| files.keep(&run, file, &redacted))
            .await
    }

    /// The kept `file` of migration `id`, when it was kept.
    ///
    /// # Errors
    ///
    /// Returns read failures and a file that is not UTF-8.
    // cancel-safe: reads only.
    pub(crate) async fn kept(&self, id: &str, file: Kept) -> Result<Option<String>, StoreError> {
        let run = id.to_owned();
        self.run(move |files| files.kept(&run, file)).await
    }
}

/// `value` as pretty JSON with a final newline.
///
/// # Errors
///
/// Returns [`StoreError::Malformed`] when it does not serialize.
fn json<T>(value: &T) -> Result<Vec<u8>, StoreError>
where
    T: Serialize,
{
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_error| StoreError::Malformed)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
