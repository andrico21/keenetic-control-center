//! The wizard's files under `<state>/migrations/<id>/`.
//!
//! - `wizard.json`: the record (`record`), which never holds a secret.
//! - `source.sealed` and `passwords.sealed`: the source configuration and the typed
//!   passwords, sealed with the backup key (XChaCha20-Poly1305, the backups' scheme) under
//!   the owner names `migration:<id>:source` and `migration:<id>:passwords`, so neither
//!   opens as a backup nor a backup as one of them.
//! - `report.json`: the redacted report of the reviewed plan.
//!
//! On unix the directories are `0700` and the files `0600`; every file is written to a
//! temporary name, synced and renamed into place.

use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use kcc_app::secrets::{CryptoError, MasterKey, SealedSecret};
use secrecy::SecretString;
use thiserror::Error;

use super::{ids::is_id, record::Record};

/// The record's file name.
const RECORD: &str = "wizard.json";

/// A sealed part of a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Sealed {
    /// The source startup configuration.
    Source,
    /// The typed passwords, as a JSON object of user names.
    Passwords,
}

impl Sealed {
    /// The part's file name.
    const fn file(self) -> &'static str {
        match self {
            Self::Source => "source.sealed",
            Self::Passwords => "passwords.sealed",
        }
    }

    /// The owner name the part is sealed under.
    fn owner(self, id: &str) -> String {
        match self {
            Self::Source => format!("migration:{id}:source"),
            Self::Passwords => format!("migration:{id}:passwords"),
        }
    }
}

/// A redacted file kept from the apply on, when the plan can no longer be built again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kept {
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
pub(super) enum StoreError {
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
pub(super) struct Store {
    /// `<state>/migrations`.
    root: PathBuf,
}

impl Store {
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
    pub(super) fn load(&self, id: &str) -> Result<Option<Record>, StoreError> {
        if !is_id(id) {
            return Ok(None);
        }
        let Some(bytes) = read(&self.root.join(id).join(RECORD))? else {
            return Ok(None);
        };
        let record: Record =
            serde_json::from_slice(&bytes).map_err(|_error| StoreError::Malformed)?;
        Ok((record.current() && record.id() == id).then_some(record))
    }

    /// Writes `record`, creating its directory.
    ///
    /// # Errors
    ///
    /// Returns write failures.
    pub(super) fn save(&self, record: &Record) -> Result<(), StoreError> {
        let mut bytes =
            serde_json::to_vec_pretty(record).map_err(|_error| StoreError::Malformed)?;
        bytes.push(b'\n');
        self.write(record.id(), RECORD, &bytes)
    }

    /// Every readable record of `owner`, newest first.
    ///
    /// # Errors
    ///
    /// Returns directory read failures.
    pub(super) fn list(&self, owner: &str) -> Result<Vec<Record>, StoreError> {
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
            if let Ok(Some(record)) = self.load(id)
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
    pub(super) fn seal(
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
    pub(super) fn open(
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

    /// Keeps the redacted `text` as `file` of migration `id`.
    ///
    /// # Errors
    ///
    /// Returns write failures.
    pub(super) fn keep(&self, id: &str, file: Kept, text: &str) -> Result<(), StoreError> {
        self.write(id, file.file(), text.as_bytes())
    }

    /// The kept `file` of migration `id`, when it was kept.
    ///
    /// # Errors
    ///
    /// Returns read failures and a file that is not UTF-8.
    pub(super) fn kept(&self, id: &str, file: Kept) -> Result<Option<String>, StoreError> {
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
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;
    use std::fs;

    use kcc_app::secrets::MasterKey;
    use secrecy::{ExposeSecret as _, SecretString};
    use tempfile::TempDir;

    use super::{Sealed, Store};
    use crate::migrate_wizard::record::Record;

    #[test]
    fn records_round_trip_and_sealed_parts_stay_bound_to_their_migration()
    -> Result<(), Box<dyn Error>> {
        let directory = TempDir::new()?;
        let store = Store::new(directory.path());
        let key = MasterKey::from_bytes([9_u8; 32]);
        let id = "1700000000-0001020304050607";
        let record = Record::new(id.to_owned(), "admin".to_owned(), 5);
        store.save(&record)?;
        let loaded = store.load(id)?.ok_or("record")?;
        assert_eq!(loaded.owner(), "admin", "round trip");
        assert!(store.load("../escape")?.is_none(), "ids are checked");
        let secret = SecretString::from("interface Bridge0\n".to_owned());
        store.seal(&key, id, Sealed::Source, &secret)?;
        let written = fs::read_to_string(
            directory
                .path()
                .join("migrations")
                .join(id)
                .join("source.sealed"),
        )?;
        assert!(!written.contains("Bridge0"), "sealed on disk");
        let opened = store.open(&key, id, Sealed::Source)?.ok_or("sealed")?;
        assert_eq!(opened.expose_secret(), secret.expose_secret(), "opens");
        let other = "1700000000-0001020304050608";
        fs::create_dir_all(directory.path().join("migrations").join(other))?;
        let copied = fs::copy(
            directory
                .path()
                .join("migrations")
                .join(id)
                .join("source.sealed"),
            directory
                .path()
                .join("migrations")
                .join(other)
                .join("source.sealed"),
        )?;
        assert!(copied > 0, "the sealed part was copied");
        assert!(
            store.open(&key, other, Sealed::Source).is_err(),
            "a copied part does not open under another migration"
        );
        assert_eq!(store.list("admin")?.len(), 1, "listed by owner");
        assert!(store.list("someone")?.is_empty(), "never another owner's");
        Ok(())
    }
}
