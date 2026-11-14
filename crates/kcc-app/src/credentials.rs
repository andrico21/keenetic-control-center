//! Encrypted router credentials managed inside the application state directory.

mod wipe;

use core::fmt;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use self::wipe::{remove_if_present, secure_remove};
use crate::{
    persist::{StateError, StateStore, create_private_dir, io_error, write_atomic},
    secrets::{CryptoError, MasterKey, SealedSecret},
};

/// Directory containing kcc-managed router credential records.
const CREDENTIALS_DIR: &str = "router-credentials";
/// Current credential-record schema.
const SCHEMA: u32 = 1;

/// A redacted failure from encrypted router credential persistence.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialError {
    /// State locking or filesystem persistence failed.
    #[error("router credential storage failed")]
    State(#[source] StateError),
    /// Sealing or opening the credential failed.
    #[error("router credential encryption failed")]
    Crypto(#[source] CryptoError),
    /// The record schema or JSON shape is unsupported.
    #[error("router credential record is invalid")]
    Record,
    /// A crash-leftover plaintext value differs from the committed sealed value.
    #[error("legacy router credential differs from the sealed record")]
    MigrationConflict,
    /// No sealed credential exists for this router.
    #[error("router credential does not exist")]
    Missing,
}

impl From<StateError> for CredentialError {
    #[inline]
    fn from(source: StateError) -> Self {
        Self::State(source)
    }
}

impl From<CryptoError> for CredentialError {
    #[inline]
    fn from(source: CryptoError) -> Self {
        Self::Crypto(source)
    }
}

/// Result of checking one legacy credential path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MigrationState {
    /// No legacy plaintext exists.
    Current,
    /// Plaintext was sealed, verified, and removed.
    Migrated,
    /// A pre-existing sealed value was verified against plaintext before removal.
    Recovered,
}

/// The kind of one kcc-managed router credential; each kind is its own sealed record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CredentialKind {
    /// Primary management password: `<id>.sealed`, the router id as associated data.
    Password,
    /// Login token: `<id>.token.sealed`, `<id>:token` as associated data.
    Token,
    /// Read-only polling password: `<id>.read.sealed`, `<id>:read` as associated data.
    ReadPassword,
}

impl CredentialKind {
    /// Every kind, in audit order.
    pub const ALL: [Self; 3] = [Self::Password, Self::Token, Self::ReadPassword];

    /// The stable name of the kind in audit entries.
    #[inline]
    #[must_use]
    pub const fn audit_name(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Token => "token",
            Self::ReadPassword => "read",
        }
    }

    /// The record file name of `router`'s credential of this kind.
    fn file_name(self, router: &str) -> String {
        match self {
            Self::Password => format!("{router}.sealed"),
            Self::Token => format!("{router}.token.sealed"),
            Self::ReadPassword => format!("{router}.read.sealed"),
        }
    }

    /// The associated data binding a record to `router` and this kind.
    fn owner(self, router: &str) -> String {
        match self {
            Self::Password => router.to_owned(),
            Self::Token => format!("{router}:token"),
            Self::ReadPassword => format!("{router}:read"),
        }
    }
}

/// One versioned sealed credential record.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRecord {
    /// Record schema.
    schema: u32,
    /// Authenticated encrypted password.
    sealed: SealedSecret,
}

/// Router credentials sealed with one process master key.
pub struct CredentialStore {
    /// State root supplying locks and the credential directory.
    state: StateStore,
    /// Master key used to seal and open records.
    key: MasterKey,
}

impl fmt::Debug for CredentialStore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialStore")
            .field("state", &self.state)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl CredentialStore {
    /// Creates a store rooted in `state` and protected by `key`.
    #[inline]
    #[must_use]
    pub const fn new(state: StateStore, key: MasterKey) -> Self {
        Self { state, key }
    }

    /// Atomically seals and replaces one managed router credential of `kind`.
    ///
    /// # Errors
    /// Returns a typed storage or cryptographic failure.
    #[inline]
    pub fn store(
        &self,
        router: &str,
        kind: CredentialKind,
        secret: &SecretString,
    ) -> Result<(), CredentialError> {
        let _lock = self.state.lock(&lock_name(router)?)?;
        self.store_locked(router, kind, secret)
    }

    /// Opens one managed router credential of `kind` into zeroizing secret memory.
    ///
    /// # Errors
    /// Returns [`CredentialError::Missing`] or a typed record/cryptographic failure.
    #[inline]
    pub fn open(
        &self,
        router: &str,
        kind: CredentialKind,
    ) -> Result<SecretString, CredentialError> {
        let path = self.sealed_path(router, kind)?;
        let bytes = fs::read(&path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                CredentialError::Missing
            } else {
                CredentialError::State(io_error(&path, source))
            }
        })?;
        let record: CredentialRecord =
            serde_json::from_slice(&bytes).map_err(|_error| CredentialError::Record)?;
        if record.schema != SCHEMA {
            return Err(CredentialError::Record);
        }
        self.key
            .open(&kind.owner(router), &record.sealed)
            .map_err(Into::into)
    }

    /// Removes every managed sealed record of `router` and its legacy plaintext; missing
    /// files are accepted.
    ///
    /// # Errors
    /// Returns a typed storage failure.
    #[inline]
    pub fn remove(&self, router: &str) -> Result<(), CredentialError> {
        CredentialKind::ALL
            .into_iter()
            .try_for_each(|kind| self.remove_kind(router, kind))
    }

    /// Removes the managed sealed record of `kind` (for a password, also the legacy
    /// plaintext); a missing file is accepted.
    ///
    /// # Errors
    /// Returns a typed storage failure.
    #[inline]
    pub fn remove_kind(&self, router: &str, kind: CredentialKind) -> Result<(), CredentialError> {
        let _lock = self.state.lock(&lock_name(router)?)?;
        remove_if_present(&self.sealed_path(router, kind)?)?;
        match kind {
            CredentialKind::Password => remove_if_present(&self.legacy_path(router)?),
            CredentialKind::Token | CredentialKind::ReadPassword => Ok(()),
        }
    }

    /// Reports whether a sealed credential of `kind` exists.
    ///
    /// # Errors
    /// Returns a typed storage failure.
    #[inline]
    pub fn exists(&self, router: &str, kind: CredentialKind) -> Result<bool, CredentialError> {
        self.sealed_path(router, kind)?
            .try_exists()
            .map_err(|source| CredentialError::State(io_error(self.state.dir(), source)))
    }

    /// Migrates one legacy plaintext credential using seal-verify-remove ordering.
    ///
    /// # Errors
    /// Leaves plaintext untouched when sealing, opening, comparison, or removal fails.
    #[inline]
    pub fn migrate(&self, router: &str) -> Result<MigrationState, CredentialError> {
        let _lock = self.state.lock(&lock_name(router)?)?;
        let legacy = self.legacy_path(router)?;
        let raw = match fs::read_to_string(&legacy) {
            Ok(value) => Zeroizing::new(value),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(MigrationState::Current);
            }
            Err(source) => return Err(CredentialError::State(io_error(&legacy, source))),
        };
        let password = SecretString::from(raw.trim_end_matches(['\r', '\n']).to_owned());
        let recovered = self.sealed_path(router, CredentialKind::Password)?.exists();
        if !recovered {
            self.store_locked(router, CredentialKind::Password, &password)?;
        }
        if self.open(router, CredentialKind::Password)?.expose_secret() != password.expose_secret()
        {
            return Err(CredentialError::MigrationConflict);
        }
        secure_remove(&legacy)?;
        Ok(if recovered {
            MigrationState::Recovered
        } else {
            MigrationState::Migrated
        })
    }

    /// Migrates every valid legacy credential in the managed directory.
    ///
    /// # Errors
    /// Stops at the first typed storage, cryptographic, or verification failure; that
    /// router's plaintext remains intact.
    #[inline]
    pub fn migrate_all(&self) -> Result<Vec<(String, MigrationState)>, CredentialError> {
        let directory = self.directory()?;
        let entries = fs::read_dir(&directory)
            .map_err(|source| CredentialError::State(io_error(&directory, source)))?;
        let mut routers = Vec::new();
        for listed in entries {
            let entry =
                listed.map_err(|source| CredentialError::State(io_error(&directory, source)))?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("password") {
                continue;
            }
            let Some(router) = path.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };
            if lock_name(router).is_ok() {
                routers.push(router.to_owned());
            }
        }
        routers.sort_unstable();
        routers
            .into_iter()
            .map(|router| self.migrate(&router).map(|state| (router, state)))
            .collect()
    }

    /// Returns whether `path` is a managed convention of `router`'s credential of `kind`:
    /// its sealed record, or for a password also the legacy plaintext path.
    ///
    /// # Errors
    /// Returns [`CredentialError::Record`] for an invalid router id.
    #[inline]
    pub fn manages(
        &self,
        router: &str,
        kind: CredentialKind,
        path: &Path,
    ) -> Result<bool, CredentialError> {
        Ok(path == self.sealed_path(router, kind)?
            || (kind == CredentialKind::Password && path == self.legacy_path(router)?))
    }

    /// Returns the managed sealed record path of `router`'s credential of `kind`.
    ///
    /// # Errors
    /// Returns [`CredentialError::Record`] for an invalid router id.
    #[inline]
    pub fn sealed_path(
        &self,
        router: &str,
        kind: CredentialKind,
    ) -> Result<PathBuf, CredentialError> {
        Ok(self.directory()?.join(kind.file_name(router)))
    }

    /// Returns the legacy plaintext path for `router`.
    ///
    /// # Errors
    /// Returns [`CredentialError::Record`] for an invalid router id.
    #[inline]
    pub fn legacy_path(&self, router: &str) -> Result<PathBuf, CredentialError> {
        Ok(self.directory()?.join(format!("{router}.password")))
    }

    /// Creates and returns the owner-only managed credential directory.
    ///
    /// # Errors
    /// Returns a typed storage failure.
    fn directory(&self) -> Result<PathBuf, CredentialError> {
        let directory = self.state.dir().join(CREDENTIALS_DIR);
        create_private_dir(&directory)?;
        Ok(directory)
    }

    /// Writes a sealed record while the caller holds its credential lock.
    ///
    /// # Errors
    /// Returns a typed storage or cryptographic failure.
    fn store_locked(
        &self,
        router: &str,
        kind: CredentialKind,
        secret: &SecretString,
    ) -> Result<(), CredentialError> {
        let directory = self.directory()?;
        let record = CredentialRecord {
            schema: SCHEMA,
            sealed: self.key.seal(&kind.owner(router), secret)?,
        };
        let mut bytes =
            serde_json::to_vec_pretty(&record).map_err(|_error| CredentialError::Record)?;
        bytes.push(b'\n');
        write_atomic(&directory, &kind.file_name(router), &bytes)?;
        Ok(())
    }
}

/// Validates `router` and returns its state-lock name.
///
/// # Errors
/// Returns [`CredentialError::Record`] for an unsafe path component.
fn lock_name(router: &str) -> Result<String, CredentialError> {
    if router.is_empty()
        || router.len() > 32
        || !router
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(CredentialError::Record);
    }
    Ok(format!("credential-{router}"))
}
