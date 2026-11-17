//! Encrypted router startup-configuration backups.
#![expect(
    clippy::absolute_paths,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    clippy::needless_pass_by_value,
    reason = "private backup helpers are documented by their typed callers and preserve owned path context"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::path::PathBuf;

use kcc_config::config_text::ParseError;
use serde::{Deserialize, Serialize};

use crate::{
    accounts::Clock,
    persist::{StateError, StateStore},
    secrets::{CryptoError, MasterKey, SealedSecret},
};

#[path = "backups/store.rs"]
mod store;

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
    /// Size in bytes of the stored configuration text.
    pub size: u64,
}

/// Readable backups of one router plus the number of files that could not be read.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct BackupListing {
    /// Readable backups, newest first.
    pub backups: Vec<BackupInfo>,
    /// Files skipped because they could not be read or parsed; they stay on disk.
    pub unreadable: usize,
}

/// Retention policy applied per router.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct BackupRetention {
    /// Maximum newest backups retained. Zero disables the count limit.
    pub keep_last: u32,
    /// Maximum backup age. Zero disables the age limit.
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
    /// Optional automatic pruning policy.
    retention: Option<BackupRetention>,
    /// Timestamp source shared by naming and retention.
    clock: Arc<dyn Clock>,
}

/// A parsed generated backup name.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct BackupName {
    /// Timestamp portion of the name.
    created_at: u64,
    /// Collision suffix, with zero representing the unsuffixed first name.
    sequence: u64,
}

/// Returns one validated router backup directory.
fn router_dir(state: &StateStore, router: &str) -> Result<PathBuf, BackupError> {
    validate_component(router, 32)?;
    Ok(state.dir().join("backups").join(router))
}

/// Validates one backup path component.
fn validate_component(value: &str, max_len: usize) -> Result<(), BackupError> {
    if (1..=max_len).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        Ok(())
    } else {
        Err(BackupError::InvalidName {
            value: value.to_owned(),
        })
    }
}

/// Parses and validates an old or collision-suffixed generated backup name.
fn parse_backup_name(name: &str) -> Result<BackupName, BackupError> {
    let invalid = || BackupError::InvalidName {
        value: name.to_owned(),
    };
    let stem = name.strip_suffix(".txt").ok_or_else(invalid)?;
    let (timestamp, remainder) = stem.split_once('-').ok_or_else(invalid)?;
    let created_at = timestamp.parse::<u64>().map_err(|_error| invalid())?;
    let (sequence, reason) = match remainder.split_once('-') {
        Some((candidate, reason)) if candidate.bytes().all(|byte| byte.is_ascii_digit()) => (
            candidate.parse::<u64>().map_err(|_error| invalid())?,
            reason,
        ),
        Some((_, _)) | None => (0, remainder),
    };
    validate_component(reason, 48)?;
    Ok(BackupName {
        created_at,
        sequence,
    })
}
