//! The wizards' files, read and written synchronously.

use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use kcc_app::secrets::{MasterKey, SealedSecret};
use secrecy::SecretString;
use serde::de::DeserializeOwned;

use super::{Kept, Sealed, StoreError};
use crate::wizard::{flow::Flow, ids::is_id, index};

/// The migrations directory of one state directory, used synchronously: on the blocking
/// pool only (see [`Store::run`](super::Store::run)).
#[derive(Debug, Clone)]
pub(crate) struct Files {
    /// `<state>/migrations`.
    root: PathBuf,
}

impl Files {
    /// The migrations directory below `state_dir`.
    pub(super) fn new(state_dir: &Path) -> Self {
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

    /// Every readable record of `owner`, newest first: only the runs the index names
    /// for `owner` are read, and names whose record is gone are dropped from the index.
    ///
    /// # Errors
    ///
    /// Returns read failures of the index.
    pub(crate) fn list<F>(&self, owner: &str) -> Result<Vec<F>, StoreError>
    where
        F: Flow,
    {
        let mut records = Vec::new();
        let mut gone = Vec::new();
        for (id, indexed) in index::runs::<F>(self)? {
            if indexed != owner {
                continue;
            }
            match self.load::<F>(&id) {
                Ok(Some(record)) if record.owner() == owner => records.push(record),
                Ok(Some(record)) => index::enter::<F>(self, &id, record.owner())?,
                Ok(None) => gone.push(id),
                Err(error) => tracing::warn!(%error, id, "a run record could not be read"),
            }
        }
        if let Err(error) = index::forget::<F>(self, &gone) {
            tracing::warn!(%error, "missing runs could not be dropped from the index");
        }
        records.sort_by(|left, right| {
            right
                .created_at()
                .cmp(&left.created_at())
                .then_with(|| right.id().cmp(left.id()))
        });
        Ok(records)
    }

    /// The runs' directory.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Deletes run `id` with every file kcc kept for it.
    ///
    /// # Errors
    ///
    /// Returns removal failures other than a missing directory.
    pub(crate) fn delete(&self, id: &str) -> Result<(), StoreError> {
        if !is_id(id) {
            return Err(StoreError::Malformed);
        }
        match fs::remove_dir_all(self.root.join(id)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
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
        let sealed = key.seal(&part.binding(id), text)?;
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
        Ok(Some(key.open(&part.binding(id), &sealed)?))
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
    pub(super) fn write(&self, id: &str, name: &str, bytes: &[u8]) -> Result<(), StoreError> {
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
