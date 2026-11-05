//! UI account persistence, password hashing and lockout accounting.

extern crate alloc;

use alloc::sync::Arc;
use core::{
    fmt::{self, Debug},
    time::Duration,
};
use std::time::SystemTime;

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher as _, PasswordVerifier as _, phc::PasswordHash},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    persist::{Migration, StateDoc, StateError, StateStore},
    secrets::{CryptoError, MasterKey, SealedSecret},
};

/// Required Argon2id memory in KiB.
pub const ARGON2_MEMORY_KIB: u32 = 19_456;
/// Required Argon2id iteration count.
pub const ARGON2_ITERATIONS: u32 = 2;
/// Required Argon2id lane count.
pub const ARGON2_LANES: u32 = 1;
/// Failed attempts before an account is locked.
pub const LOCKOUT_FAILURES: u32 = 5;
/// Minimum accepted password length in Unicode scalar values.
pub const MIN_PASSWORD_CHARS: usize = 12;
/// Maximum accepted password length in Unicode scalar values.
pub const MAX_PASSWORD_CHARS: usize = 128;

/// A Unix timestamp source, injectable so lockout tests never sleep.
pub trait Clock: Debug + Send + Sync {
    /// Seconds since the Unix epoch.
    fn unix_seconds(&self) -> u64;
}

/// The operating system wall clock.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct SystemClock;

impl Clock for SystemClock {
    #[inline]
    fn unix_seconds(&self) -> u64 {
        SystemTime::UNIX_EPOCH
            .elapsed()
            .map_or(0, |elapsed| elapsed.as_secs())
    }
}

/// A persisted UI account. The password hash is encrypted at rest and its
/// `Debug` representation never exposes ciphertext or hash material.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Account {
    /// Login name.
    pub username: String,
    /// Encrypted Argon2id PHC string, bound to the username as AAD.
    pub password_hash: SealedSecret,
    /// Granted role name.
    pub role: String,
    /// Preferred locale.
    pub locale: String,
    /// Whether login is administratively disabled.
    pub disabled: bool,
    /// Consecutive failed attempts before the current time.
    pub failure_count: u32,
    /// Unix timestamp through which login is locked.
    pub lockout_until: Option<u64>,
}

impl Debug for Account {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            username,
            password_hash: _,
            role,
            locale,
            disabled,
            failure_count,
            lockout_until,
        } = self;
        f.debug_struct("Account")
            .field("username", username)
            .field("password_hash", &"<redacted>")
            .field("role", role)
            .field("locale", locale)
            .field("disabled", disabled)
            .field("failure_count", failure_count)
            .field("lockout_until", lockout_until)
            .finish()
    }
}

/// Accounts persisted in `users.json`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct UsersDocument {
    /// UI accounts.
    pub users: Vec<Account>,
}

impl StateDoc for UsersDocument {
    const FILE_NAME: &'static str = "users.json";
    const SCHEMA: u32 = 1;
    const MIGRATIONS: &'static [Migration] = &[];
}

/// Account creation input. The password is deliberately non-serializable and
/// redacted by `SecretString`'s `Debug` implementation.
#[derive(Debug)]
#[non_exhaustive]
pub struct NewAccount {
    /// Login name.
    pub username: String,
    /// Plaintext password consumed during creation and never stored.
    pub password: SecretString,
    /// Granted role name.
    pub role: String,
    /// Preferred locale.
    pub locale: String,
    /// Initial administrative state.
    pub disabled: bool,
}

impl NewAccount {
    /// Builds account input; policy validation runs when it is persisted by
    /// [`AccountStore::create`].
    #[inline]
    #[must_use]
    pub fn new(username: String, password: SecretString, role: String) -> Self {
        Self {
            username,
            password,
            role,
            locale: "en".to_owned(),
            disabled: false,
        }
    }

    /// Sets the preferred locale.
    #[inline]
    #[must_use]
    pub fn with_locale(mut self, locale: String) -> Self {
        self.locale = locale;
        self
    }

    /// Sets the initial administrative state.
    #[inline]
    #[must_use]
    pub const fn with_disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }
}

/// Authentication result with no secret-bearing fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Authentication {
    /// Password matched and the account is enabled and unlocked.
    Authenticated {
        /// Role granted to the caller.
        role: String,
        /// Preferred locale.
        locale: String,
    },
    /// Credentials were invalid or no such account exists.
    Invalid,
    /// The account is administratively disabled.
    Disabled,
    /// The account is locked until this Unix timestamp.
    Locked {
        /// End of the lockout window.
        until: u64,
    },
}

/// Account service errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AccountError {
    /// State storage failed.
    #[error(transparent)]
    State(#[from] StateError),
    /// Secret encryption or decryption failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Password hashing failed without exposing the password.
    #[error("password hashing failed")]
    PasswordHash,
    /// A stored password hash is malformed.
    #[error("stored password hash is malformed")]
    StoredPasswordHash,
    /// Username violates the length or character policy.
    #[error("username must be 1..=64 characters from [a-z0-9._-]")]
    InvalidUsername,
    /// Password violates the length policy.
    #[error("password must be 12..=128 characters")]
    InvalidPasswordLength,
    /// Password equals the username.
    #[error("password must not equal username")]
    PasswordEqualsUsername,
    /// Username already exists.
    #[error("account already exists")]
    DuplicateAccount,
}

/// UI account service using the state store's locking and atomic writes.
#[derive(Debug)]
#[non_exhaustive]
pub struct AccountStore {
    /// Versioned state storage.
    state: StateStore,
    /// Encryption key for password hashes.
    key: MasterKey,
    /// Lockout duration.
    lockout: Duration,
    /// Injectable wall clock.
    clock: Arc<dyn Clock>,
}

impl AccountStore {
    /// Creates an account service.
    #[inline]
    #[must_use]
    pub fn new(
        state: StateStore,
        key: MasterKey,
        lockout: Duration,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            state,
            key,
            lockout,
            clock,
        }
    }

    /// Creates and persists a UI account.
    ///
    /// # Errors
    ///
    /// Returns a policy, hashing, encryption, duplicate, or state error.
    #[inline]
    pub fn create(&self, new: NewAccount) -> Result<(), AccountError> {
        validate_username(&new.username)?;
        validate_password(&new.username, &new.password)?;
        let hash = hash_password(&new.password)?;
        let sealed = self.key.seal(&new.username, &SecretString::from(hash))?;
        let account = Account {
            username: new.username,
            password_hash: sealed,
            role: new.role,
            locale: new.locale,
            disabled: new.disabled,
            failure_count: 0,
            lockout_until: None,
        };
        self.state.update(|document: &mut UsersDocument| {
            if document
                .users
                .iter()
                .any(|existing| existing.username == account.username)
            {
                return Err(AccountError::DuplicateAccount);
            }
            document.users.push(account);
            Ok(())
        })??;
        Ok(())
    }

    /// Authenticates a password and atomically updates failure/lockout state.
    ///
    /// # Errors
    ///
    /// Returns a state, decryption, or stored-hash error. Error text never
    /// contains the supplied password or stored hash.
    #[inline]
    pub fn authenticate(
        &self,
        username: &str,
        password: &SecretString,
    ) -> Result<Authentication, AccountError> {
        let now = self.clock.unix_seconds();
        let lockout_seconds = self.lockout.as_secs();
        let key = &self.key;
        self.state.update(|document: &mut UsersDocument| {
            let Some(account) = document
                .users
                .iter_mut()
                .find(|candidate| candidate.username == username)
            else {
                verify_dummy_password(password)?;
                return Ok(Authentication::Invalid);
            };
            if account.disabled {
                return Ok(Authentication::Disabled);
            }
            if let Some(until) = account.lockout_until {
                if now < until {
                    return Ok(Authentication::Locked { until });
                }
                account.failure_count = 0;
                account.lockout_until = None;
            }
            let hash = key.open(&account.username, &account.password_hash)?;
            if verify_password(password, &hash)? {
                account.failure_count = 0;
                account.lockout_until = None;
                return Ok(Authentication::Authenticated {
                    role: account.role.clone(),
                    locale: account.locale.clone(),
                });
            }
            account.failure_count = account.failure_count.saturating_add(1);
            if account.failure_count >= LOCKOUT_FAILURES {
                let until = now.saturating_add(lockout_seconds);
                account.lockout_until = Some(until);
                return Ok(Authentication::Locked { until });
            }
            Ok(Authentication::Invalid)
        })?
    }

    /// Whether at least one enabled administrator account exists.
    ///
    /// # Errors
    ///
    /// Returns a state error when `users.json` cannot be read.
    #[inline]
    pub fn has_admin(&self) -> Result<bool, AccountError> {
        Ok(self.state.read::<UsersDocument>()?.is_some_and(|document| {
            document
                .users
                .iter()
                .any(|account| account.role == "admin" && !account.disabled)
        }))
    }

    /// Replaces `username`'s password after verifying the current password.
    ///
    /// The returned authentication result deliberately has the same shape as
    /// [`Self::authenticate`], so a web boundary can keep credential failures
    /// uniform. Password hashing uses the same fixed Argon2id parameters as
    /// account creation.
    ///
    /// # Errors
    ///
    /// Returns an account, password-policy, hashing, encryption, or state error.
    #[inline]
    pub fn change_password(
        &self,
        username: &str,
        current_password: &SecretString,
        new_password: &SecretString,
    ) -> Result<Authentication, AccountError> {
        let authentication = self.authenticate(username, current_password)?;
        if !matches!(
            authentication,
            Authentication::Authenticated { role: _, locale: _ }
        ) {
            return Ok(authentication);
        }
        validate_password(username, new_password)?;
        let hash = hash_password(new_password)?;
        let sealed = self.key.seal(username, &SecretString::from(hash))?;
        self.state.update(|document: &mut UsersDocument| {
            if let Some(account) = document
                .users
                .iter_mut()
                .find(|candidate| candidate.username == username)
            {
                account.password_hash = sealed;
                account.failure_count = 0;
                account.lockout_until = None;
            }
        })?;
        Ok(authentication)
    }

    /// Updates the preferred locale of an existing account.
    ///
    /// Returns `false` when the account disappeared before the update.
    ///
    /// # Errors
    ///
    /// Returns a state error when `users.json` cannot be updated.
    #[inline]
    pub fn set_locale(&self, username: &str, locale: String) -> Result<bool, AccountError> {
        self.state
            .update(|document: &mut UsersDocument| {
                let Some(account) = document
                    .users
                    .iter_mut()
                    .find(|candidate| candidate.username == username)
                else {
                    return false;
                };
                account.locale = locale;
                true
            })
            .map_err(AccountError::from)
    }
}

/// Returns the exact OWASP Argon2id parameters used for password creation.
///
/// # Errors
///
/// This reports an Argon2 parameter error if the fixed constants become invalid.
#[inline]
pub const fn password_params() -> Result<Params, argon2::Error> {
    Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_LANES, None)
}

/// Hashes a password with Argon2id v19 and an OS-generated salt.
///
/// # Errors
///
/// Returns [`AccountError::PasswordHash`] if parameter setup, randomness, or
/// hashing fails.
fn hash_password(password: &SecretString) -> Result<String, AccountError> {
    let params = password_params().map_err(|_error| AccountError::PasswordHash)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password(password.expose_secret().as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|_error| AccountError::PasswordHash)
}

/// Verifies a supplied password against a stored PHC string.
///
/// # Errors
///
/// Returns [`AccountError::StoredPasswordHash`] if the persisted hash is not a
/// valid PHC string.
fn verify_password(password: &SecretString, hash: &SecretString) -> Result<bool, AccountError> {
    let parsed = PasswordHash::new(hash.expose_secret())
        .map_err(|_error| AccountError::StoredPasswordHash)?;
    Ok(Argon2::default()
        .verify_password(password.expose_secret().as_bytes(), &parsed)
        .is_ok())
}

/// Performs the same Argon2id work for an unknown username without needing a
/// persisted hash. The fixed salt is public and exists only to equalize login
/// work; no derived bytes leave this function.
///
/// # Errors
///
/// Returns [`AccountError::PasswordHash`] if the fixed Argon2 parameters or
/// hashing operation fail.
fn verify_dummy_password(password: &SecretString) -> Result<(), AccountError> {
    let params = password_params().map_err(|_error| AccountError::PasswordHash)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0_u8; 32];
    argon2
        .hash_password_into(
            password.expose_secret().as_bytes(),
            b"kcc-unknown-user",
            &mut output,
        )
        .map_err(|_error| AccountError::PasswordHash)
}

/// Applies the account username boundary policy.
///
/// # Errors
///
/// Returns [`AccountError::InvalidUsername`] when the boundary policy fails.
fn validate_username(username: &str) -> Result<(), AccountError> {
    let valid_length = (1..=64).contains(&username.len());
    let valid_chars = username
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte));
    (valid_length && valid_chars)
        .then_some(())
        .ok_or(AccountError::InvalidUsername)
}

/// Applies the account password boundary policy without exposing the value.
///
/// # Errors
///
/// Returns a length or username-equality policy error.
fn validate_password(username: &str, password: &SecretString) -> Result<(), AccountError> {
    let plaintext = password.expose_secret();
    let count = plaintext.chars().count();
    if !(MIN_PASSWORD_CHARS..=MAX_PASSWORD_CHARS).contains(&count) {
        return Err(AccountError::InvalidPasswordLength);
    }
    if plaintext == username {
        return Err(AccountError::PasswordEqualsUsername);
    }
    Ok(())
}
