//! Encrypted router startup-configuration backups.
#![expect(
    clippy::absolute_paths,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    clippy::needless_pass_by_value,
    reason = "private backup helpers are documented by their typed callers and preserve owned path context"
)]

use core::time::Duration;
use std::{fs, io, path::PathBuf, time::SystemTime};

use kcc_config::config_text::{ParseError, normalize};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    persist::{StateError, StateStore, create_private_dir, io_error, write_atomic},
    secrets::{CryptoError, MasterKey, SealedSecret},
};

/// Metadata for one encrypted backup.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct BackupInfo {
    /// File name relative to the router backup directory.
    pub name: String,
    /// Creation time as Unix seconds.
    pub created_at: u64,
    /// Caller-supplied safe reason.
    pub reason: String,
}

/// Retention policy applied per router.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct BackupRetention {
    /// Maximum newest backups retained.
    pub keep_last: u32,
    /// Maximum backup age.
    pub max_age: Duration,
}

/// A normalized line-oriented configuration difference.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct BackupDiff {
    /// Canonical lines present only in the older backup.
    pub removed: Vec<String>,
    /// Canonical lines present only in the newer backup.
    pub added: Vec<String>,
}

/// Backup storage failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BackupError {
    /// State storage failed.
    #[error(transparent)]
    State(#[from] StateError),
    /// Encryption failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Backup JSON is malformed.
    #[error("backup {name} is malformed")]
    Malformed {
        /// Backup file name.
        name: String,
    },
    /// A backup name, router id, or reason is unsafe.
    #[error("invalid backup component {value:?}")]
    InvalidName {
        /// Rejected value.
        value: String,
    },
    /// The requested backup does not exist.
    #[error("backup {name} was not found")]
    NotFound {
        /// Backup file name.
        name: String,
    },
    /// Configuration normalization failed.
    #[error(transparent)]
    Config(#[from] ParseError),
}

/// Serialized encrypted backup payload.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupRecord {
    /// Creation time as Unix seconds.
    created_at: u64,
    /// Backup reason.
    reason: String,
    /// Encrypted configuration text.
    sealed: SealedSecret,
}

/// Encrypted backup store rooted below a [`StateStore`].
#[derive(Debug)]
pub struct BackupStore {
    /// State directory owner.
    state: StateStore,
    /// Encryption key.
    key: MasterKey,
}

impl BackupStore {
    /// Creates a backup store.
    #[inline]
    #[must_use]
    pub const fn new(state: StateStore, key: MasterKey) -> Self {
        Self { state, key }
    }

    /// The key sealing the backups. A front end keeping its own encrypted state beside
    /// them (the Web UI migration wizard) seals with it under owner names of its own, so
    /// its ciphertexts never open as a backup and no backup opens as one of them.
    #[inline]
    #[must_use]
    pub const fn key(&self) -> &MasterKey {
        &self.key
    }

    /// Stores encrypted startup configuration and returns its metadata.
    ///
    /// # Errors
    ///
    /// Returns validation, encryption, serialization, or state I/O errors.
    pub fn create(
        &self,
        router: &str,
        reason: &str,
        text: &SecretString,
    ) -> Result<BackupInfo, BackupError> {
        validate_component(router, 32)?;
        validate_component(reason, 48)?;
        let created_at = unix_seconds(SystemTime::now());
        let name = format!("{created_at}-{reason}.txt");
        let directory = self.router_dir(router)?;
        create_private_dir(&directory)?;
        let _lock = self.state.lock(&format!("backup-{router}"))?;
        let record = BackupRecord {
            created_at,
            reason: reason.to_owned(),
            sealed: self.key.seal(&backup_owner(router, &name), text)?,
        };
        let mut bytes = serde_json::to_vec(&record)
            .map_err(|_error| BackupError::Malformed { name: name.clone() })?;
        bytes.push(b'\n');
        write_atomic(&directory, &name, &bytes)?;
        Ok(BackupInfo {
            name,
            created_at,
            reason: reason.to_owned(),
        })
    }

    /// Lists backups newest first.
    ///
    /// # Errors
    ///
    /// Returns validation, directory I/O, or malformed-record errors.
    pub fn list(&self, router: &str) -> Result<Vec<BackupInfo>, BackupError> {
        let directory = self.router_dir(router)?;
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(io_error(&directory, error).into()),
        };
        let mut backups = Vec::new();
        for listed in entries {
            let entry = listed.map_err(|error| io_error(&directory, error))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !name.ends_with(".txt") {
                continue;
            }
            let record = read_record(entry.path(), &name)?;
            backups.push(BackupInfo {
                name,
                created_at: record.created_at,
                reason: record.reason,
            });
        }
        backups.sort_by_key(|backup| core::cmp::Reverse(backup.created_at));
        Ok(backups)
    }

    /// Opens and decrypts one backup.
    ///
    /// # Errors
    ///
    /// Returns validation, missing-file, malformed-record, I/O, or decryption errors.
    pub fn get(&self, router: &str, name: &str) -> Result<SecretString, BackupError> {
        let path = self.backup_path(router, name)?;
        let record = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<BackupRecord>(&bytes).map_err(|_error| {
                BackupError::Malformed {
                    name: name.to_owned(),
                }
            })?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(BackupError::NotFound {
                    name: name.to_owned(),
                });
            }
            Err(error) => return Err(io_error(&path, error).into()),
        };
        self.key
            .open(&backup_owner(router, name), &record.sealed)
            .map_err(BackupError::from)
    }

    /// Deletes one backup.
    ///
    /// # Errors
    ///
    /// Returns validation, missing-file, lock, or I/O errors.
    pub fn delete(&self, router: &str, name: &str) -> Result<(), BackupError> {
        let path = self.backup_path(router, name)?;
        let _lock = self.state.lock(&format!("backup-{router}"))?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(BackupError::NotFound {
                name: name.to_owned(),
            }),
            Err(error) => Err(io_error(&path, error).into()),
        }
    }

    /// Prunes backups outside the count or age policy and returns deleted names.
    ///
    /// # Errors
    ///
    /// Returns list, lock, validation, or I/O errors.
    pub fn retain(
        &self,
        router: &str,
        policy: BackupRetention,
    ) -> Result<Vec<String>, BackupError> {
        let now = unix_seconds(SystemTime::now());
        let backups = self.list(router)?;
        let keep = usize::try_from(policy.keep_last).unwrap_or(usize::MAX);
        let mut removed = Vec::new();
        for (index, backup) in backups.into_iter().enumerate() {
            let too_many = index >= keep;
            let too_old = now.saturating_sub(backup.created_at) > policy.max_age.as_secs();
            if too_many || too_old {
                self.delete(router, &backup.name)?;
                removed.push(backup.name);
            }
        }
        Ok(removed)
    }

    /// Diffs two backups after canonical configuration normalization.
    ///
    /// # Errors
    ///
    /// Returns backup read/decryption or configuration parse errors.
    pub fn diff(&self, router: &str, older: &str, newer: &str) -> Result<BackupDiff, BackupError> {
        let older_text = self.get(router, older)?;
        let newer_text = self.get(router, newer)?;
        let old_normalized = normalize(older_text.expose_secret())?;
        let new_normalized = normalize(newer_text.expose_secret())?;
        let old_lines = old_normalized.lines().collect::<Vec<_>>();
        let new_lines = new_normalized.lines().collect::<Vec<_>>();
        Ok(BackupDiff {
            removed: old_lines
                .iter()
                .filter(|line| !new_lines.contains(line))
                .map(|line| (*line).to_owned())
                .collect(),
            added: new_lines
                .iter()
                .filter(|line| !old_lines.contains(line))
                .map(|line| (*line).to_owned())
                .collect(),
        })
    }

    /// Returns the validated router backup directory.
    fn router_dir(&self, router: &str) -> Result<PathBuf, BackupError> {
        validate_component(router, 32)?;
        Ok(self.state.dir().join("backups").join(router))
    }

    /// Returns one validated backup path.
    fn backup_path(&self, router: &str, name: &str) -> Result<PathBuf, BackupError> {
        validate_backup_name(name)?;
        Ok(self.router_dir(router)?.join(name))
    }
}

/// Reads one encrypted backup record.
fn read_record(path: PathBuf, name: &str) -> Result<BackupRecord, BackupError> {
    let bytes = fs::read(&path).map_err(|error| io_error(&path, error))?;
    serde_json::from_slice(&bytes).map_err(|_error| BackupError::Malformed {
        name: name.to_owned(),
    })
}

/// Builds associated data binding a backup to its router and file.
fn backup_owner(router: &str, name: &str) -> String {
    format!("backup:{router}:{name}")
}

/// Converts a system time to Unix seconds.
fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Validates one backup path component.
fn validate_component(value: &str, max_len: usize) -> Result<(), BackupError> {
    if !(1..=max_len).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(BackupError::InvalidName {
            value: value.to_owned(),
        });
    }
    Ok(())
}

/// Validates one generated backup file name.
fn validate_backup_name(name: &str) -> Result<(), BackupError> {
    let Some(stem) = name.strip_suffix(".txt") else {
        return Err(BackupError::InvalidName {
            value: name.to_owned(),
        });
    };
    let Some((timestamp, reason)) = stem.split_once('-') else {
        return Err(BackupError::InvalidName {
            value: name.to_owned(),
        });
    };
    if timestamp.parse::<u64>().is_err() {
        return Err(BackupError::InvalidName {
            value: name.to_owned(),
        });
    }
    validate_component(reason, 48)
}
