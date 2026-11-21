//! The sealed enrolment record and private key of a router's SSH access, and their removal.

use core::fmt;
use std::fs;

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use super::{
    Part, SshStateError, lock, open_sealed, read_file, remove_if_present, router_id, write_sealed,
};
use crate::{
    credentials::router_id::RouterId,
    persist::{StateStore, io_error},
    secrets::MasterKey,
};

/// The SSH port of a new enrolment record (Entware's dropbear default on Keenetic).
pub const DEFAULT_PORT: u16 = 222;
/// Lock scope of the enrolment record and the key.
const LOCK_SCOPE: &str = "router-ssh";
/// Lock scope of the probe ticket.
pub(super) const TICKET_LOCK_SCOPE: &str = "router-ssh-ticket";

/// Whether the router's host key is pinned and kcc's key installed.
#[expect(
    clippy::module_name_repetitions,
    reason = "callers read it beside `SshEnrolment` as `EnrolmentState::Active`"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnrolmentState {
    /// Not (or not yet completely) enrolled; operations are refused.
    Pending,
    /// Enrolled: the pin and the installed key are in use.
    Active,
}

/// One router's SSH enrolment. Holds public values only: no password, no private key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SshEnrolment {
    /// Whether SSH management is switched on for the router.
    pub enabled: bool,
    /// The SSH port.
    pub port: u16,
    /// Pending or active.
    pub state: EnrolmentState,
    /// The router URL host the pin was taken for.
    pub router_host: Option<String>,
    /// The pinned host key as an OpenSSH public line, `ssh-ed25519 <base64>`.
    pub host_key: Option<String>,
    /// The pinned host key's fingerprint, `SHA256:<base64>`.
    pub fingerprint: Option<String>,
    /// When the router was enrolled, in Unix seconds.
    pub enrolled_at: Option<u64>,
    /// Who enrolled the router.
    pub enrolled_by: Option<String>,
}

impl Default for SshEnrolment {
    /// A new record: enabled, port 222, pending, nothing pinned.
    #[inline]
    fn default() -> Self {
        Self {
            enabled: true,
            port: DEFAULT_PORT,
            state: EnrolmentState::Pending,
            router_host: None,
            host_key: None,
            fingerprint: None,
            enrolled_at: None,
            enrolled_by: None,
        }
    }
}

/// The enrolment records and private keys, sealed with one master key.
pub struct SshStore {
    /// State root holding `router-ssh/` and the locks.
    state: StateStore,
    /// Master key sealing every file.
    key: MasterKey,
}

impl fmt::Debug for SshStore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshStore")
            .field("state", &self.state)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl SshStore {
    /// A store rooted in `state` and sealed with `key`.
    #[inline]
    #[must_use]
    pub const fn new(state: StateStore, key: MasterKey) -> Self {
        Self { state, key }
    }

    /// The enrolment record of `router`, `None` when there is none.
    ///
    /// # Errors
    /// [`SshStateError::InvalidRouter`], [`SshStateError::Record`] for a damaged record or
    /// another schema, [`SshStateError::Crypto`] for another master key or another record's
    /// file, or a storage failure.
    #[inline]
    pub fn load(&self, router: &str) -> Result<Option<SshEnrolment>, SshStateError> {
        let id = router_id(router)?;
        self.load_record(id)
    }

    /// Seals and replaces the enrolment record of `router`.
    ///
    /// # Errors
    /// [`SshStateError::InvalidRouter`], [`SshStateError::InvalidPort`] for port 0, or a
    /// storage or cryptographic failure.
    #[inline]
    pub fn save(&self, router: &str, record: &SshEnrolment) -> Result<(), SshStateError> {
        let id = router_id(router)?;
        let _lock = lock(&self.state, LOCK_SCOPE, id)?;
        self.save_record(id, record)
    }

    /// The private key of `router` (OpenSSH text), `None` when there is none.
    ///
    /// # Errors
    /// As [`Self::load`].
    #[inline]
    pub fn load_key(&self, router: &str) -> Result<Option<SecretString>, SshStateError> {
        let id = router_id(router)?;
        let path = super::directory(&self.state)?.join(Part::Key.file_name(id));
        read_file(&path)?
            .map(|bytes| open_sealed(&self.key, (id, Part::Key), &bytes))
            .transpose()
    }

    /// Seals and replaces the private key of `router`.
    ///
    /// # Errors
    /// [`SshStateError::InvalidRouter`], or a storage or cryptographic failure.
    #[inline]
    pub fn save_key(&self, router: &str, private_key: &SecretString) -> Result<(), SshStateError> {
        let id = router_id(router)?;
        let _lock = lock(&self.state, LOCK_SCOPE, id)?;
        write_sealed((&self.state, &self.key), (id, Part::Key), private_key)
    }

    /// Sets the SSH port of `router`, creating a default record when there is none; the
    /// pin and the state are kept.
    ///
    /// # Errors
    /// As [`Self::save`], plus the errors of [`Self::load`].
    #[inline]
    pub fn set_port(&self, router: &str, port: u16) -> Result<SshEnrolment, SshStateError> {
        self.edit(router, |record| record.port = port)
    }

    /// Switches SSH management of `router` on or off, creating a default record when there
    /// is none; the pin and the state are kept.
    ///
    /// # Errors
    /// As [`Self::set_port`].
    #[inline]
    pub fn set_enabled(&self, router: &str, enabled: bool) -> Result<SshEnrolment, SshStateError> {
        self.edit(router, |record| record.enabled = enabled)
    }

    /// Applies `change` to the record of `router` (a default one when absent) under its lock.
    ///
    /// # Errors
    /// As [`Self::set_port`].
    fn edit<F>(&self, router: &str, change: F) -> Result<SshEnrolment, SshStateError>
    where
        F: FnOnce(&mut SshEnrolment),
    {
        let id = router_id(router)?;
        let _lock = lock(&self.state, LOCK_SCOPE, id)?;
        let mut record = self.load_record(id)?.unwrap_or_default();
        change(&mut record);
        self.save_record(id, &record)?;
        Ok(record)
    }

    /// Reads and opens the record of `id`.
    ///
    /// # Errors
    /// As [`Self::load`].
    fn load_record(&self, id: RouterId<'_>) -> Result<Option<SshEnrolment>, SshStateError> {
        let path = super::directory(&self.state)?.join(Part::State.file_name(id));
        let Some(bytes) = read_file(&path)? else {
            return Ok(None);
        };
        let text = open_sealed(&self.key, (id, Part::State), &bytes)?;
        serde_json::from_str(text.expose_secret())
            .map(Some)
            .map_err(|_error| SshStateError::Record)
    }

    /// Seals and writes the record of `id`; the caller holds its lock.
    ///
    /// # Errors
    /// As [`Self::save`].
    fn save_record(&self, id: RouterId<'_>, record: &SshEnrolment) -> Result<(), SshStateError> {
        if record.port == 0 {
            return Err(SshStateError::InvalidPort);
        }
        let text = serde_json::to_string(record).map_err(|_error| SshStateError::Record)?;
        write_sealed(
            (&self.state, &self.key),
            (id, Part::State),
            &SecretString::from(text),
        )
    }
}

/// Whether `router`'s enrolment is active, so the router may still authorize kcc's key.
///
/// A record that exists but cannot be opened counts as active: the caller then warns
/// rather than stays silent about a key that may still be installed.
#[inline]
#[must_use]
pub fn active(store: &SshStore, router: &str) -> bool {
    match store.load(router) {
        Ok(Some(record)) => record.state == EnrolmentState::Active,
        Ok(None) | Err(SshStateError::InvalidRouter) => false,
        Err(_) => true,
    }
}

/// Removes every SSH file of `router`: its record, key, ticket and any ticket being
/// redeemed. Files of other routers (`ab` beside `a`) are never touched; absent files are
/// accepted.
///
/// # Errors
/// [`SshStateError::InvalidRouter`], or a storage failure.
#[inline]
pub fn forget(state: &StateStore, router: &str) -> Result<(), SshStateError> {
    let id = router_id(router)?;
    let _record_lock = lock(state, LOCK_SCOPE, id)?;
    let _ticket_lock = lock(state, TICKET_LOCK_SCOPE, id)?;
    let directory = super::directory(state)?;
    for part in [Part::State, Part::Key, Part::Ticket] {
        remove_if_present(&directory.join(part.file_name(id)))?;
    }
    let redeeming = format!("{}.ticket.redeem.", id.as_str());
    let entries = fs::read_dir(&directory).map_err(|error| io_error(&directory, error))?;
    for listed in entries {
        let entry = listed.map_err(|error| io_error(&directory, error))?;
        let name = entry.file_name();
        if name
            .to_str()
            .and_then(|text| text.strip_prefix(redeeming.as_str()))
            .is_some_and(|suffix| !suffix.is_empty())
        {
            remove_if_present(&entry.path())?;
        }
    }
    Ok(())
}
