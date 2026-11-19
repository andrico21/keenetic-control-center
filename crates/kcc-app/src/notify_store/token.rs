//! The Telegram bot token, sealed with the master key under `notify:telegram` at
//! `<state>/notify/telegram.token.sealed`.
//!
//! The token is pasted once and never shown again: nothing here prints, logs or returns
//! it except [`NotifySecrets::token`], which hands it out in a [`SecretString`].

use std::{
    fs, io,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use super::{NotifyError, NotifyRuntime};
use crate::{
    persist::{StateStore, create_private_dir, io_error, write_atomic},
    secrets::{MasterKey, SealedSecret, binding::Binding},
};

/// Directory of the sealed token below the state directory.
const DIR: &str = "notify";
/// File name of the sealed token.
const FILE: &str = "telegram.token.sealed";
/// State lock serializing writers of the token file.
const LOCK: &str = "notify-token";
/// Current token record schema; records of any other schema are refused.
const SCHEMA: u32 = 1;

/// One versioned sealed token record.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRecord {
    /// Record schema.
    schema: u32,
    /// Authenticated encrypted token.
    sealed: SealedSecret,
}

/// Stores, opens and removes the sealed Telegram bot token.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct NotifySecrets;

impl NotifySecrets {
    /// Seals `token` into the token file, replacing any earlier one, and records in
    /// `notify_state.json` when it was set (clearing an earlier rejection).
    ///
    /// The token must look like a Bot API token: 1 to 20 digits, `:`, then 30 to 64 of
    /// `A-Z a-z 0-9 _ -`.
    ///
    /// # Errors
    ///
    /// [`NotifyError::Invalid`] naming `token` (never quoting it) for another shape, or a
    /// storage or cryptographic failure.
    #[inline]
    pub fn set_token(
        state: &StateStore,
        key: &MasterKey,
        token: &SecretString,
    ) -> Result<(), NotifyError> {
        if !well_formed(token.expose_secret()) {
            return Err(NotifyError::Invalid { field: "token" });
        }
        let _lock = state.lock(LOCK)?;
        let record = TokenRecord {
            schema: SCHEMA,
            sealed: key.seal(&Binding::notify_telegram(), token)?,
        };
        let mut bytes = serde_json::to_vec_pretty(&record).map_err(|_error| NotifyError::Record)?;
        bytes.push(b'\n');
        let dir = state.dir().join(DIR);
        create_private_dir(&dir)?;
        write_atomic(&dir, FILE, &bytes)?;
        let now = unix_now();
        state.update(|runtime: &mut NotifyRuntime| {
            runtime.token_set_at = Some(now);
            runtime.token_rejected_at = None;
        })?;
        Ok(())
    }

    /// Opens the sealed token; `None` when none is set.
    ///
    /// # Errors
    ///
    /// [`NotifyError::Record`] for a record of another schema or shape,
    /// [`NotifyError::Crypto`] for a wrong key or a value sealed for another record, or a
    /// storage failure.
    #[inline]
    pub fn token(state: &StateStore, key: &MasterKey) -> Result<Option<SecretString>, NotifyError> {
        let path = path(state);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(&path, error).into()),
        };
        let record: TokenRecord =
            serde_json::from_slice(&bytes).map_err(|_error| NotifyError::Record)?;
        if record.schema != SCHEMA {
            return Err(NotifyError::Record);
        }
        Ok(Some(key.open(&Binding::notify_telegram(), &record.sealed)?))
    }

    /// Removes the token file (an absent one is accepted) and the record of when it was
    /// set or rejected.
    ///
    /// # Errors
    ///
    /// A storage failure.
    #[inline]
    pub fn clear(state: &StateStore) -> Result<(), NotifyError> {
        let _lock = state.lock(LOCK)?;
        let path = path(state);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(&path, error).into()),
        }
        state.update(|runtime: &mut NotifyRuntime| {
            runtime.token_set_at = None;
            runtime.token_rejected_at = None;
        })?;
        Ok(())
    }
}

/// The token file of `state`.
fn path(state: &StateStore) -> PathBuf {
    state.dir().join(DIR).join(FILE)
}

/// Whether `token` has the Bot API token shape `^[0-9]{1,20}:[A-Za-z0-9_-]{30,64}$`.
fn well_formed(token: &str) -> bool {
    token.split_once(':').is_some_and(|(bot, secret)| {
        (1..=20).contains(&bot.len())
            && bot.bytes().all(|byte| byte.is_ascii_digit())
            && (30..=64).contains(&secret.len())
            && secret
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}

/// The current time in Unix seconds; 0 before the epoch.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
