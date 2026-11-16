//! The state store: a private directory of versioned JSON files.
//!
//! - The directory is created owner-only (`0700` on unix) and every file is
//!   written owner-only (`0600`).
//! - Writes are atomic: a temp file in the same directory is written, synced
//!   and renamed over the target, then the directory is synced. A temp file a
//!   crash left behind is never read and is replaced by the next write.
//! - Every file is `{"schema": N, ...}`. Older schemas are upgraded through the
//!   document's migration registry (after copying the directory to
//!   `pre-migration-<schema>-<ts>/`); newer schemas are refused.
//! - Every read-modify-write holds an exclusive advisory lock on
//!   `<file>.lock`; router write leases are `leases/<router>.lock`.

use core::fmt::Display;
use std::{
    fs::{self, DirBuilder, File, OpenOptions, TryLockError},
    io::{self, Write as _},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, error::Category};

use crate::settings::is_valid_name;

pub mod private_file;

/// Key holding the schema version in every state file.
const SCHEMA_KEY: &str = "schema";
/// Subdirectory for per-router write leases.
const LEASES_DIR: &str = "leases";
/// Suffix of lock sidecar files.
const LOCK_SUFFIX: &str = ".lock";

/// Error from the state store.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StateError {
    /// A file system operation failed.
    #[error("state I/O on {path}: {source}")]
    Io {
        /// Path the operation touched.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// Another process or handle holds the lock.
    #[error("state is locked by another process: {path}")]
    StateLocked {
        /// Lock file that is held.
        path: PathBuf,
    },
    /// The file was written by a newer release.
    #[error("{file} has schema {found}, newer than the supported {supported}; upgrade kcc")]
    SchemaTooNew {
        /// State file name.
        file: String,
        /// Schema found in the file.
        found: u32,
        /// Newest schema this build understands.
        supported: u32,
    },
    /// No migration is registered for an old schema.
    #[error("{file}: no migration registered from schema {from}")]
    MigrationMissing {
        /// State file name.
        file: String,
        /// Schema without a migration.
        from: u32,
    },
    /// A migration step failed.
    #[error("{file}: migration from schema {from} failed: {reason}")]
    Migration {
        /// State file name.
        file: String,
        /// Schema the step started from.
        from: u32,
        /// Why it failed.
        reason: String,
    },
    /// The file is not a valid versioned state document.
    #[error("{file} is not a valid state file: {reason}")]
    Corrupt {
        /// State file name.
        file: String,
        /// What is wrong.
        reason: String,
    },
    /// A state file, lock or lease name is not a safe path component.
    #[error("invalid state name {name:?}")]
    InvalidName {
        /// The rejected name.
        name: String,
    },
}

/// What the closure of [`StateStore::update_if_changed`] did to the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Edit<R> {
    /// The document changed and is written back.
    Changed(R),
    /// Nothing changed; the file stays as it is.
    Unchanged(R),
}

/// A migration step body: takes and returns the document without `schema`.
pub type MigrateFn = fn(Map<String, Value>) -> Result<Map<String, Value>, String>;

/// One schema upgrade step: turns a schema-`from` document into schema `from + 1`.
///
/// The step receives and returns the document without the `schema` key.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Migration {
    /// Schema this step upgrades from.
    pub from: u32,
    /// The upgrade.
    pub apply: MigrateFn,
}

impl Migration {
    /// Registers a step from `from` to `from + 1`.
    #[inline]
    #[must_use]
    pub const fn new(from: u32, apply: MigrateFn) -> Self {
        Self { from, apply }
    }
}

/// A document stored as one versioned JSON state file.
///
/// It must serialize to a JSON object without a `schema` key.
pub trait StateDoc: Serialize + DeserializeOwned + Default {
    /// File name inside the state directory.
    const FILE_NAME: &'static str;
    /// Current schema version.
    const SCHEMA: u32;
    /// Upgrade steps from older schemas.
    const MIGRATIONS: &'static [Migration];
}

/// An exclusive advisory lock, released on drop.
#[derive(Debug)]
#[non_exhaustive]
pub struct StateLock {
    /// Locked handle; closing it releases the lock.
    _handle: File,
    /// Path of the lock file.
    path: PathBuf,
}

impl StateLock {
    /// Path of the lock file.
    #[inline]
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Handle to the state directory.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StateStore {
    /// The state directory.
    dir: PathBuf,
}

impl StateStore {
    /// Opens (creating owner-only if needed) the state directory at `dir`.
    ///
    /// # Errors
    ///
    /// [`StateError::Io`] when the directory cannot be created or restricted.
    #[inline]
    pub fn open(dir: &Path) -> Result<Self, StateError> {
        create_private_dir(dir)?;
        Ok(Self {
            dir: dir.to_owned(),
        })
    }

    /// The state directory.
    #[inline]
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Reads `T`, upgrading an older schema in memory. `None` if absent.
    ///
    /// Takes no lock: writes are atomic renames, so a reader sees either the
    /// old or the new file.
    ///
    /// # Errors
    ///
    /// [`StateError::SchemaTooNew`], a migration error, [`StateError::Corrupt`]
    /// or [`StateError::Io`].
    #[inline]
    pub fn read<T>(&self) -> Result<Option<T>, StateError>
    where
        T: StateDoc,
    {
        Ok(self.load::<T>()?.map(|(doc, _found)| doc))
    }

    /// Read-modify-write of `T` under its exclusive lock, blocking until the
    /// lock is free. A missing file starts from `T::default()`. An upgraded
    /// document is written back at the current schema, after the directory
    /// was copied to `pre-migration-<schema>-<ts>/`.
    ///
    /// # Errors
    ///
    /// As [`Self::read`], plus write failures.
    #[inline]
    pub fn update<T, F, R>(&self, mutate: F) -> Result<R, StateError>
    where
        T: StateDoc,
        F: FnOnce(&mut T) -> R,
    {
        self.update_if_changed(|doc: &mut T| Edit::Changed(mutate(doc)))
    }

    /// As [`Self::update`], but the file is written only when `mutate` answers
    /// [`Edit::Changed`] (or the document was upgraded from an older schema); after
    /// [`Edit::Unchanged`] it keeps its bytes and time.
    ///
    /// # Errors
    ///
    /// As [`Self::update`].
    #[inline]
    pub fn update_if_changed<T, F, R>(&self, mutate: F) -> Result<R, StateError>
    where
        T: StateDoc,
        F: FnOnce(&mut T) -> Edit<R>,
    {
        let _lock = self.lock(T::FILE_NAME)?;
        let (mut doc, upgraded) = match self.load::<T>()? {
            Some((doc, found)) => {
                let upgraded = found < T::SCHEMA;
                if upgraded {
                    self.backup_before_migration(found)?;
                }
                (doc, upgraded)
            }
            None => (T::default(), false),
        };
        let (result, changed) = match mutate(&mut doc) {
            Edit::Changed(result) => (result, true),
            Edit::Unchanged(result) => (result, false),
        };
        if changed || upgraded {
            self.write_locked(&doc)?;
        }
        Ok(result)
    }

    /// Replaces `T` under its exclusive lock, blocking until the lock is free.
    ///
    /// # Errors
    ///
    /// [`StateError::Io`] or [`StateError::Corrupt`] when `T` does not
    /// serialize to an object.
    #[inline]
    pub fn write<T>(&self, doc: &T) -> Result<(), StateError>
    where
        T: StateDoc,
    {
        let _lock = self.lock(T::FILE_NAME)?;
        self.write_locked(doc)
    }

    /// Takes the exclusive lock for state file `name`, waiting while another
    /// process holds it.
    ///
    /// # Errors
    ///
    /// [`StateError::InvalidName`] or [`StateError::Io`].
    #[inline]
    pub fn lock(&self, name: &str) -> Result<StateLock, StateError> {
        let path = self.lock_path(name)?;
        let handle = open_lock_file(&path)?;
        handle.lock().map_err(|source| io_error(&path, source))?;
        Ok(StateLock {
            _handle: handle,
            path,
        })
    }

    /// Takes the exclusive lock for state file `name` without waiting.
    ///
    /// # Errors
    ///
    /// [`StateError::StateLocked`] when it is held, otherwise as [`Self::lock`].
    #[inline]
    pub fn try_lock(&self, name: &str) -> Result<StateLock, StateError> {
        let path = self.lock_path(name)?;
        try_lock_path(path)
    }

    /// Takes the write lease of router `router` (`leases/<router>.lock`)
    /// without waiting.
    ///
    /// # Errors
    ///
    /// [`StateError::StateLocked`] when another process holds the lease,
    /// [`StateError::InvalidName`] or [`StateError::Io`].
    #[inline]
    pub fn try_lease(&self, router: &str) -> Result<StateLock, StateError> {
        check_name(router)?;
        let leases = self.dir.join(LEASES_DIR);
        create_private_dir(&leases)?;
        try_lock_path(leases.join(format!("{router}{LOCK_SUFFIX}")))
    }

    /// Path of the lock sidecar of state file `name`.
    ///
    /// # Errors
    ///
    /// [`StateError::InvalidName`].
    fn lock_path(&self, name: &str) -> Result<PathBuf, StateError> {
        check_name(name)?;
        Ok(self.dir.join(format!("{name}{LOCK_SUFFIX}")))
    }

    /// Reads and upgrades `T`, returning it with the schema found on disk.
    ///
    /// # Errors
    ///
    /// As [`Self::read`].
    fn load<T>(&self) -> Result<Option<(T, u32)>, StateError>
    where
        T: StateDoc,
    {
        let path = self.dir.join(T::FILE_NAME);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(&path, error)),
        };
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|error| corrupt_json(T::FILE_NAME, &error))?;
        upgrade::<T>(value).map(Some)
    }

    /// Serializes and atomically writes `T`; the caller holds its lock.
    ///
    /// # Errors
    ///
    /// [`StateError::Corrupt`] or [`StateError::Io`].
    fn write_locked<T>(&self, doc: &T) -> Result<(), StateError>
    where
        T: StateDoc,
    {
        let Value::Object(mut map) =
            serde_json::to_value(doc).map_err(|error| corrupt(T::FILE_NAME, &error))?
        else {
            return Err(corrupt(T::FILE_NAME, "document is not a JSON object"));
        };
        let mut out = Map::new();
        drop(out.insert(SCHEMA_KEY.to_owned(), Value::from(T::SCHEMA)));
        out.append(&mut map);
        let mut bytes = serde_json::to_vec_pretty(&Value::Object(out))
            .map_err(|error| corrupt_json(T::FILE_NAME, &error))?;
        bytes.push(b'\n');
        write_atomic(&self.dir, T::FILE_NAME, &bytes)
    }

    /// Copies the top-level state files to `pre-migration-<schema>-<ts>/`.
    ///
    /// # Errors
    ///
    /// [`StateError::Io`].
    fn backup_before_migration(&self, schema: u32) -> Result<(), StateError> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis());
        let backup = self.dir.join(format!("pre-migration-{schema}-{millis}"));
        create_private_dir(&backup)?;
        let entries = fs::read_dir(&self.dir).map_err(|error| io_error(&self.dir, error))?;
        for listed in entries {
            let entry = listed.map_err(|error| io_error(&self.dir, error))?;
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            let file_type = entry
                .file_type()
                .map_err(|error| io_error(&entry.path(), error))?;
            if file_type.is_dir()
                || file_type.is_symlink()
                || name.starts_with('.')
                || name.ends_with(LOCK_SUFFIX)
            {
                continue;
            }
            let bytes = fs::read(entry.path()).map_err(|error| io_error(&entry.path(), error))?;
            write_atomic(&backup, name, &bytes)?;
        }
        Ok(())
    }
}

/// Checks the schema of a parsed file and runs the migrations it needs.
///
/// # Errors
///
/// [`StateError::SchemaTooNew`], a migration error or [`StateError::Corrupt`].
fn upgrade<T>(value: Value) -> Result<(T, u32), StateError>
where
    T: StateDoc,
{
    let file = T::FILE_NAME;
    let Value::Object(mut map) = value else {
        return Err(corrupt(file, "not a JSON object"));
    };
    let found = map
        .remove(SCHEMA_KEY)
        .and_then(|schema| schema.as_u64())
        .and_then(|schema| u32::try_from(schema).ok())
        .ok_or_else(|| corrupt(file, "missing or invalid \"schema\""))?;
    if found > T::SCHEMA {
        return Err(StateError::SchemaTooNew {
            file: file.to_owned(),
            found,
            supported: T::SCHEMA,
        });
    }
    let mut current = found;
    while current < T::SCHEMA {
        let step = T::MIGRATIONS
            .iter()
            .find(|step| step.from == current)
            .ok_or_else(|| StateError::MigrationMissing {
                file: file.to_owned(),
                from: current,
            })?;
        map = (step.apply)(map).map_err(|reason| StateError::Migration {
            file: file.to_owned(),
            from: current,
            reason,
        })?;
        drop(map.remove(SCHEMA_KEY));
        current = current.saturating_add(1);
    }
    let doc =
        serde_json::from_value(Value::Object(map)).map_err(|error| corrupt_json(file, &error))?;
    Ok((doc, found))
}

/// Writes `bytes` to `dir/name` atomically: owner-only temp file in the same
/// directory, `fsync`, rename over the target, then sync the directory.
///
/// For files below the state directory whose writers hold the target's lock
/// (see [`StateStore::lock`]): the temp name is fixed per target, so any temp
/// file found here was left by a crash and is removed first. Outside the
/// state directory use [`private_file::replace`].
///
/// # Errors
///
/// [`StateError::Io`].
#[inline]
pub fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), StateError> {
    let temp = dir.join(format!(".{name}.tmp"));
    remove_if_present(&temp)?;
    publish(&temp, &dir.join(name), bytes)?;
    sync_dir(dir)
}

/// Writes `bytes` to the new owner-only file `temp` and renames it over `target`.
///
/// `temp` is created exclusively, so an existing entry there (a symbolic link
/// included) is never followed or reused. The file is synced before the rename;
/// a temp file this call created is removed again when a later step fails.
///
/// # Errors
///
/// [`StateError::Io`].
fn publish(temp: &Path, target: &Path, bytes: &[u8]) -> Result<(), StateError> {
    let mut file = create_private_file(temp)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let published = written
        .map_err(|error| io_error(temp, error))
        .and_then(|()| fs::rename(temp, target).map_err(|error| io_error(target, error)));
    if published.is_err() {
        // Best-effort cleanup of our own temp file; the first error is what the caller needs.
        drop(fs::remove_file(temp));
    }
    published
}

/// Writes `bytes` durably to a new `dir/name` without replacing an existing file.
///
/// Returns `false` when the target already exists. The caller serializes users of the
/// fixed temporary name with its domain lock.
///
/// # Errors
///
/// [`StateError::Io`].
pub(crate) fn write_exclusive(dir: &Path, name: &str, bytes: &[u8]) -> Result<bool, StateError> {
    let target = dir.join(name);
    let temp = dir.join(format!(".{name}.tmp"));
    remove_if_present(&temp)?;
    let mut file = create_private_file(&temp)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error(&temp, error))?;
    drop(file);
    let linked = fs::hard_link(&temp, &target);
    fs::remove_file(&temp).map_err(|error| io_error(&temp, error))?;
    match linked {
        Ok(()) => {
            sync_dir(dir)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(io_error(&target, error)),
    }
}

/// Removes `path`, treating "already gone" as success.
///
/// # Errors
///
/// [`StateError::Io`].
fn remove_if_present(path: &Path) -> Result<(), StateError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(path, error)),
    }
}

/// Opens (creating owner-only) a lock file and tries to lock it.
///
/// # Errors
///
/// [`StateError::StateLocked`] or [`StateError::Io`].
fn try_lock_path(path: PathBuf) -> Result<StateLock, StateError> {
    let handle = open_lock_file(&path)?;
    match handle.try_lock() {
        Ok(()) => Ok(StateLock {
            _handle: handle,
            path,
        }),
        Err(TryLockError::WouldBlock) => Err(StateError::StateLocked { path }),
        Err(TryLockError::Error(error)) => Err(io_error(&path, error)),
    }
}

/// Opens or creates a lock file, owner-only.
///
/// # Errors
///
/// [`StateError::Io`].
fn open_lock_file(path: &Path) -> Result<File, StateError> {
    let mut options = OpenOptions::new();
    let _: &mut OpenOptions = options.read(true).write(true).create(true).truncate(false);
    restrict_options(&mut options);
    let file = options.open(path).map_err(|error| io_error(path, error))?;
    restrict_file(&file, path)?;
    Ok(file)
}

/// Creates a new owner-only file; fails if it exists (no symlink following).
///
/// # Errors
///
/// [`StateError::Io`], including when the file exists.
pub(crate) fn create_private_file(path: &Path) -> Result<File, StateError> {
    let mut options = OpenOptions::new();
    let _: &mut OpenOptions = options.write(true).create_new(true);
    restrict_options(&mut options);
    let file = options.open(path).map_err(|error| io_error(path, error))?;
    restrict_file(&file, path)?;
    Ok(file)
}

/// Opens or creates an owner-only appendable state file.
///
/// This is exposed within the crate for append-only stores such as the audit
/// log, while preserving the same owner-only permissions as versioned state.
///
/// # Errors
///
/// [`StateError::Io`] when the file cannot be opened or restricted.
pub(crate) fn open_private_append_file(path: &Path) -> Result<File, StateError> {
    let mut options = OpenOptions::new();
    let _: &mut OpenOptions = options.append(true).create(true);
    restrict_options(&mut options);
    let file = options.open(path).map_err(|error| io_error(path, error))?;
    restrict_file(&file, path)?;
    Ok(file)
}

/// Creates `dir` (and parents) owner-only and restricts an existing one.
///
/// Only for directories kcc owns: an existing `dir` is changed to `0700`.
///
/// # Errors
///
/// [`StateError::Io`].
#[inline]
pub fn create_private_dir(dir: &Path) -> Result<(), StateError> {
    let mut builder = DirBuilder::new();
    let _: &mut DirBuilder = builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let _: &mut DirBuilder = builder.mode(0o700);
    }
    builder.create(dir).map_err(|error| io_error(dir, error))?;
    #[cfg(windows)]
    restrict_windows(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|error| io_error(dir, error))?;
    }
    Ok(())
}

/// Asks for mode `0600` at creation on unix.
fn restrict_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let _: &mut OpenOptions = options.mode(0o600);
    }
    #[cfg(not(unix))]
    {
        let _: &mut OpenOptions = options;
    }
}

/// Forces mode `0600` on an open file on unix, regardless of the umask.
///
/// # Errors
///
/// [`StateError::Io`].
fn restrict_file(file: &File, path: &Path) -> Result<(), StateError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| io_error(path, error))?;
    }
    #[cfg(not(unix))]
    {
        let _: (&File, &Path) = (file, path);
    }
    #[cfg(windows)]
    restrict_windows(path)?;
    Ok(())
}

/// Applies a protected owner-only DACL on Windows.
///
/// # Errors
/// Returns [`StateError::Io`] when Windows rejects the descriptor or DACL update.
#[cfg(windows)]
fn restrict_windows(path: &Path) -> Result<(), StateError> {
    use core::str::FromStr as _;

    use windows_permissions::{LocalBox, SecurityDescriptor, WindowsSecure as _};

    let descriptor = LocalBox::<SecurityDescriptor>::from_str("D:P(A;;GA;;;OW)")
        .map_err(|source| io_error(path, source))?;
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| io_error(path, io::Error::other("owner-only DACL was not created")))?;
    let mut name = path.as_os_str();
    name.set_dacl(dacl)
        .map_err(|source| io_error(path, source))?;
    Ok(())
}

/// Syncs a directory so a rename inside it is durable (unix only).
///
/// # Errors
///
/// [`StateError::Io`].
fn sync_dir(dir: &Path) -> Result<(), StateError> {
    #[cfg(unix)]
    {
        File::open(dir)
            .and_then(|handle| handle.sync_all())
            .map_err(|error| io_error(dir, error))?;
    }
    #[cfg(not(unix))]
    {
        let _: &Path = dir;
    }
    Ok(())
}

/// Rejects names that are not a single safe path component.
///
/// # Errors
///
/// [`StateError::InvalidName`].
fn check_name(name: &str) -> Result<(), StateError> {
    if is_valid_name(name) {
        Ok(())
    } else {
        Err(StateError::InvalidName {
            name: name.to_owned(),
        })
    }
}

/// Builds a [`StateError::Io`].
pub(crate) fn io_error(path: &Path, source: io::Error) -> StateError {
    StateError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Builds a [`StateError::Corrupt`].
fn corrupt(file: &str, reason: &(impl Display + ?Sized)) -> StateError {
    StateError::Corrupt {
        file: file.to_owned(),
        reason: reason.to_string(),
    }
}

/// Builds a value-free JSON corruption error.
fn corrupt_json(file: &str, error: &serde_json::Error) -> StateError {
    let category = match error.classify() {
        Category::Io => "I/O",
        Category::Syntax => "syntax",
        Category::Data => "data",
        Category::Eof => "end of input",
    };
    StateError::Corrupt {
        file: file.to_owned(),
        reason: format!(
            "{category} at line {}, column {}",
            error.line(),
            error.column()
        ),
    }
}
