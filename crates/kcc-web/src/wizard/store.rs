//! The wizards' files under `<state>/migrations/<id>/`.
//!
//! - the record, named by its wizard ([`Flow::FILE`]: `wizard.json` for a migration,
//!   `preset.json` for a preset run), which never holds a secret.
//! - `source.sealed` and `passwords.sealed`: the source configuration and the typed
//!   passwords, sealed with the backup key (XChaCha20-Poly1305, the backups' scheme) under
//!   the owner names `migration:<id>:source` and `migration:<id>:passwords`, so neither
//!   opens as a backup nor a backup as one of them.
//! - `report.json`: the redacted report of the reviewed plan.
//!
//! On unix the directories are `0700` and the files `0600`; every file is written to a
//! temporary name, synced and renamed into place.
//!
//! Each wizard reads only records under its own file name, so neither opens the other's
//! runs; a preset run seals a copied (transient) preset as [`Sealed::Preset`].

use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use kcc_app::secrets::{CryptoError, MasterKey, SealedSecret};
use secrecy::SecretString;
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

use super::{flow::Flow, ids::is_id};

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

    /// The owner name the part is sealed under.
    fn owner(self, id: &str) -> String {
        match self {
            Self::Source => format!("migration:{id}:source"),
            Self::Passwords => format!("migration:{id}:passwords"),
            Self::Preset => format!("preset-run:{id}:preset"),
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
#[derive(Debug, Clone)]
pub(crate) struct Store {
    /// `<state>/migrations`.
    root: PathBuf,
}

impl Store {
    /// The migrations directory below `state_dir`.
    pub(crate) fn new(state_dir: &Path) -> Self {
        Self {
            root: state_dir.join("migrations"),
        }
    }

    /// The record `id`, when it exists and is in the current format.
    ///
    /// # Errors
    ///
    /// Returns read failures and malformed records.
    pub(crate) fn load<F>(&self, id: &str) -> Result<Option<F>, StoreError>
    where
        F: Flow,
    {
        let Some(record) = self.load_named::<F>(id, F::FILE)? else {
            return Ok(None);
        };
        Ok((record.current() && record.id() == id).then_some(record))
    }

    /// Writes `record`, creating its directory.
    ///
    /// # Errors
    ///
    /// Returns write failures.
    pub(crate) fn save<F>(&self, record: &F) -> Result<(), StoreError>
    where
        F: Flow,
    {
        self.save_named(record.id(), F::FILE, record)
    }

    /// Every readable record of `owner`, newest first.
    ///
    /// # Errors
    ///
    /// Returns directory read failures.
    pub(crate) fn list<F>(&self, owner: &str) -> Result<Vec<F>, StoreError>
    where
        F: Flow,
    {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut records = Vec::new();
        for entry in entries {
            let name = entry?.file_name();
            let Some(id) = name.to_str() else {
                continue;
            };
            if let Ok(Some(record)) = self.load::<F>(id)
                && record.owner() == owner
            {
                records.push(record);
            }
        }
        records.sort_by(|left, right| {
            right
                .created_at()
                .cmp(&left.created_at())
                .then_with(|| right.id().cmp(left.id()))
        });
        Ok(records)
    }

    /// Seals `text` as `part` of migration `id` with `key`.
    ///
    /// # Errors
    ///
    /// Returns sealing and write failures.
    pub(crate) fn seal(
        &self,
        key: &MasterKey,
        id: &str,
        part: Sealed,
        text: &SecretString,
    ) -> Result<(), StoreError> {
        let sealed = key.seal(&part.owner(id), text)?;
        let mut bytes = serde_json::to_vec(&sealed).map_err(|_error| StoreError::Malformed)?;
        bytes.push(b'\n');
        self.write(id, part.file(), &bytes)
    }

    /// Opens `part` of migration `id` with `key`, when it was sealed.
    ///
    /// # Errors
    ///
    /// Returns read, format and opening failures.
    pub(crate) fn open(
        &self,
        key: &MasterKey,
        id: &str,
        part: Sealed,
    ) -> Result<Option<SecretString>, StoreError> {
        let Some(bytes) = read(&self.root.join(id).join(part.file()))? else {
            return Ok(None);
        };
        let sealed: SealedSecret =
            serde_json::from_slice(&bytes).map_err(|_error| StoreError::Malformed)?;
        Ok(Some(key.open(&part.owner(id), &sealed)?))
    }

    /// Writes `value` as JSON to `file` of run `id`, creating its directory.
    ///
    /// # Errors
    ///
    /// Returns serialization and write failures.
    pub(crate) fn save_named<T>(&self, id: &str, file: &str, value: &T) -> Result<(), StoreError>
    where
        T: Serialize,
    {
        let mut bytes = serde_json::to_vec_pretty(value).map_err(|_error| StoreError::Malformed)?;
        bytes.push(b'\n');
        self.write(id, file, &bytes)
    }

    /// The JSON `file` of run `id`, when it exists.
    ///
    /// # Errors
    ///
    /// Returns read failures and a file that does not parse as `T`.
    pub(crate) fn load_named<T>(&self, id: &str, file: &str) -> Result<Option<T>, StoreError>
    where
        T: DeserializeOwned,
    {
        if !is_id(id) {
            return Ok(None);
        }
        read(&self.root.join(id).join(file))?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|_error| StoreError::Malformed))
            .transpose()
    }

    /// The ids of every directory below the migrations directory, of either wizard.
    ///
    /// # Errors
    ///
    /// Returns directory read failures.
    pub(crate) fn ids(&self) -> Result<Vec<String>, StoreError> {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut ids = Vec::new();
        for entry in entries {
            if let Some(id) = entry?.file_name().to_str().filter(|name| is_id(name)) {
                ids.push(id.to_owned());
            }
        }
        Ok(ids)
    }

    /// Deletes `part` of run `id`, when it was sealed.
    ///
    /// # Errors
    ///
    /// Returns removal failures other than a missing file.
    pub(crate) fn discard(&self, id: &str, part: Sealed) -> Result<(), StoreError> {
        if !is_id(id) {
            return Err(StoreError::Malformed);
        }
        match fs::remove_file(self.root.join(id).join(part.file())) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Keeps the redacted `text` as `file` of migration `id`.
    ///
    /// # Errors
    ///
    /// Returns write failures.
    pub(crate) fn keep(&self, id: &str, file: Kept, text: &str) -> Result<(), StoreError> {
        self.write(id, file.file(), text.as_bytes())
    }

    /// The kept `file` of migration `id`, when it was kept.
    ///
    /// # Errors
    ///
    /// Returns read failures and a file that is not UTF-8.
    pub(crate) fn kept(&self, id: &str, file: Kept) -> Result<Option<String>, StoreError> {
        if !is_id(id) {
            return Ok(None);
        }
        read(&self.root.join(id).join(file.file()))?
            .map(|bytes| String::from_utf8(bytes).map_err(|_error| StoreError::Malformed))
            .transpose()
    }

    /// Writes `bytes` to `name` in migration `id`'s directory, owner-only.
    ///
    /// # Errors
    ///
    /// Returns directory, file, sync or rename failures.
    fn write(&self, id: &str, name: &str, bytes: &[u8]) -> Result<(), StoreError> {
        if !is_id(id) {
            return Err(StoreError::Malformed);
        }
        let directory = self.root.join(id);
        let mut builder = DirBuilder::new();
        let _: &mut DirBuilder = builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            let _: &mut DirBuilder = builder.mode(0o700);
        }
        builder.create(&directory)?;
        let temporary = directory.join(format!("{name}.tmp"));
        let mut options = OpenOptions::new();
        let _: &mut OpenOptions = options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            let _: &mut OpenOptions = options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, directory.join(name))?;
        Ok(())
    }
}

/// The bytes of `path`, or `None` when it does not exist.
///
/// # Errors
///
/// Returns read failures other than a missing file.
fn read(path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
