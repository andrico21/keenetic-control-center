//! Backup store operations.

extern crate alloc;

use alloc::sync::Arc;
use core::cmp::Reverse;
use std::{fs, io, path::PathBuf};

use kcc_config::config_text::normalize;
use secrecy::{ExposeSecret as _, SecretString};

use super::{
    BackupDiff, BackupError, BackupInfo, BackupListing, BackupName, BackupRecord, BackupRetention,
    BackupStore, parse_backup_name, router_dir, validate_component,
};
use crate::{
    accounts::{Clock, SystemClock},
    persist::{create_private_dir, io_error, write_exclusive},
    secrets::{MasterKey, binding::Binding},
};

impl BackupRetention {
    /// Creates a per-router backup retention policy.
    #[inline]
    #[must_use]
    pub const fn new(max_age: core::time::Duration, keep_last: u32) -> Self {
        Self { keep_last, max_age }
    }
}

impl BackupStore {
    /// Creates a backup store without automatic pruning.
    #[inline]
    #[must_use]
    pub fn new(state: crate::persist::StateStore, key: MasterKey) -> Self {
        Self {
            state,
            key,
            retention: None,
            clock: Arc::new(SystemClock),
        }
    }

    /// Applies `retention` after each successful create.
    #[inline]
    #[must_use]
    pub const fn with_retention(mut self, retention: BackupRetention) -> Self {
        self.retention = Some(retention);
        self
    }

    /// Uses `clock` for backup timestamps and age retention.
    #[inline]
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The key sealing the backups. A front end keeping its own encrypted state beside
    /// them seals with it under owner names of its own.
    #[inline]
    #[must_use]
    pub const fn key(&self) -> &MasterKey {
        &self.key
    }

    /// Stores encrypted startup configuration and returns its metadata.
    ///
    /// # Errors
    ///
    /// Returns validation, encryption, serialization, or state I/O errors. Automatic
    /// retention failures are logged and do not turn a completed create into a failure.
    pub fn create(
        &self,
        router: &str,
        reason: &str,
        text: &SecretString,
    ) -> Result<BackupInfo, BackupError> {
        validate_component(router, 32)?;
        validate_component(reason, 48)?;
        let created_at = self.clock.unix_seconds();
        let directory = router_dir(&self.state, router)?;
        create_private_dir(&directory)?;
        let _lock = self.state.lock(&format!("backup-{router}"))?;
        let mut sequence = 0_u64;
        let info = loop {
            let name = if sequence == 0 {
                format!("{created_at}-{reason}.txt")
            } else {
                format!("{created_at}-{sequence}-{reason}.txt")
            };
            let record = BackupRecord {
                created_at,
                reason: reason.to_owned(),
                sealed: self.key.seal(&Binding::backup(router, &name), text)?,
            };
            let mut bytes = serde_json::to_vec(&record)
                .map_err(|_error| BackupError::Malformed { name: name.clone() })?;
            bytes.push(b'\n');
            if write_exclusive(&directory, &name, &bytes)? {
                break BackupInfo {
                    name,
                    created_at,
                    reason: reason.to_owned(),
                };
            }
            sequence = sequence.saturating_add(1);
        };
        if let Some(policy) = self.retention
            && let Err(error) = self.retain_locked(router, policy, Some(&info.name))
        {
            tracing::warn!(router, %error, "backup retention failed after create");
        }
        Ok(info)
    }

    /// Lists readable backups newest first, skipping unreadable files.
    ///
    /// # Errors
    ///
    /// Returns validation or directory I/O errors.
    pub fn list(&self, router: &str) -> Result<Vec<BackupInfo>, BackupError> {
        Ok(self.list_unlocked(router)?.backups)
    }

    /// Lists readable backups newest first and counts the unreadable files left in place.
    ///
    /// # Errors
    ///
    /// Returns validation or directory I/O errors.
    pub fn listing(&self, router: &str) -> Result<BackupListing, BackupError> {
        self.list_unlocked(router)
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
            .open(&Binding::backup(router, name), &record.sealed)
            .map_err(BackupError::from)
    }

    /// Deletes one backup.
    ///
    /// # Errors
    ///
    /// Returns validation, missing-file, lock, or I/O errors.
    pub fn delete(&self, router: &str, name: &str) -> Result<(), BackupError> {
        let _lock = self.state.lock(&format!("backup-{router}"))?;
        self.delete_unlocked(router, name)
    }

    /// Prunes backups outside the count or age policy and returns deleted names.
    ///
    /// Zero count and age values disable their respective limits.
    ///
    /// # Errors
    ///
    /// Returns list, lock, validation, or I/O errors.
    pub fn retain(
        &self,
        router: &str,
        policy: BackupRetention,
    ) -> Result<Vec<String>, BackupError> {
        let _lock = self.state.lock(&format!("backup-{router}"))?;
        self.retain_locked(router, policy, None)
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

    /// Lists backups without acquiring the router lock.
    ///
    /// A file that cannot be read or parsed is left untouched, logged by name and counted.
    fn list_unlocked(&self, router: &str) -> Result<BackupListing, BackupError> {
        let directory = router_dir(&self.state, router)?;
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(BackupListing::default());
            }
            Err(error) => return Err(io_error(&directory, error).into()),
        };
        let mut backups = Vec::new();
        let mut unreadable = 0_usize;
        for listed in entries {
            let entry = listed.map_err(|error| io_error(&directory, error))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !name.ends_with(".txt") {
                continue;
            }
            let record = match read_record(entry.path(), &name) {
                Ok(record) => record,
                Err(error) => {
                    tracing::warn!(router, file = %name, %error, "unreadable backup skipped");
                    unreadable = unreadable.saturating_add(1);
                    continue;
                }
            };
            backups.push(BackupInfo {
                name,
                created_at: record.created_at,
                reason: record.reason,
            });
        }
        backups.sort_by_key(|backup| {
            Reverse(parse_backup_name(&backup.name).unwrap_or(BackupName {
                created_at: backup.created_at,
                sequence: 0,
            }))
        });
        Ok(BackupListing {
            backups,
            unreadable,
        })
    }

    /// Applies retention while the caller owns the router lock.
    fn retain_locked(
        &self,
        router: &str,
        policy: BackupRetention,
        protected: Option<&str>,
    ) -> Result<Vec<String>, BackupError> {
        let now = self.clock.unix_seconds();
        let backups = self.list_unlocked(router)?.backups;
        let keep = usize::try_from(policy.keep_last).unwrap_or(usize::MAX);
        let mut removed = Vec::new();
        for (index, backup) in backups.into_iter().enumerate() {
            let count_applies = policy.keep_last > 0 && index >= keep;
            let age_applies = !policy.max_age.is_zero()
                && now.saturating_sub(backup.created_at) > policy.max_age.as_secs();
            if protected != Some(backup.name.as_str()) && (count_applies || age_applies) {
                self.delete_unlocked(router, &backup.name)?;
                removed.push(backup.name);
            }
        }
        Ok(removed)
    }

    /// Deletes one backup while the caller owns the router lock.
    fn delete_unlocked(&self, router: &str, name: &str) -> Result<(), BackupError> {
        let path = self.backup_path(router, name)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(BackupError::NotFound {
                name: name.to_owned(),
            }),
            Err(error) => Err(io_error(&path, error).into()),
        }
    }

    /// Returns one validated backup path.
    fn backup_path(&self, router: &str, name: &str) -> Result<PathBuf, BackupError> {
        let _: BackupName = parse_backup_name(name)?;
        Ok(router_dir(&self.state, router)?.join(name))
    }
}

/// Reads one encrypted backup record.
fn read_record(path: PathBuf, name: &str) -> Result<BackupRecord, BackupError> {
    let bytes = fs::read(&path).map_err(|error| io_error(&path, error))?;
    serde_json::from_slice(&bytes).map_err(|_error| BackupError::Malformed {
        name: name.to_owned(),
    })
}
