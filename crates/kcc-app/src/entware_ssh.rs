//! Per-router SSH state for Entware management, sealed under the master key in
//! `<state>/router-ssh/`.
//!
//! Each router `<id>` owns at most these files, and no others:
//!
//! - `<id>.sealed`: the enrolment record ([`state::SshEnrolment`]), bound to
//!   `router:<id>:ssh-state`;
//! - `<id>.key.sealed`: kcc's OpenSSH private key for the router, bound to
//!   `router:<id>:ssh-key`;
//! - `<id>.ticket.sealed`: the single-use probe ticket ([`ticket::TicketStore`]), bound to
//!   `router:<id>:ssh-ticket`, and `<id>.ticket.redeem.<random>` while one is redeemed.
//!
//! Router ids hold no `.`, so no file of one router is a name of another router. The state
//! holds no password and lives neither in `kcc.toml` nor in `routers.json`.

pub mod state;
pub mod ticket;

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::{
    credentials::router_id::RouterId,
    persist::{StateError, StateLock, StateStore, create_private_dir, io_error, write_atomic},
    secrets::{CryptoError, MasterKey, SealedSecret, binding::Binding},
};

/// Directory of the SSH state below the state directory.
const SSH_DIR: &str = "router-ssh";
/// Schema of every sealed SSH file; files of another schema are refused.
const SCHEMA: u32 = 1;

/// A failure of the SSH state or ticket store. Never carries a secret, a nonce or a key.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SshStateError {
    /// The router id breaks the router id rule.
    #[error("invalid router id")]
    InvalidRouter,
    /// The SSH port is 0.
    #[error("invalid SSH port")]
    InvalidPort,
    /// State locking or file persistence failed.
    #[error("router SSH state storage failed")]
    State(#[source] StateError),
    /// Sealing or opening failed: another master key, another record or tampered data.
    #[error("router SSH state encryption failed")]
    Crypto(#[source] CryptoError),
    /// A file is not a record of the supported schema and shape.
    #[error("router SSH state record is invalid")]
    Record,
    /// The probe ticket was refused.
    #[error("SSH probe ticket refused: {0}")]
    Ticket(TicketRefusal),
}

impl From<StateError> for SshStateError {
    #[inline]
    fn from(source: StateError) -> Self {
        Self::State(source)
    }
}

impl From<CryptoError> for SshStateError {
    #[inline]
    fn from(source: CryptoError) -> Self {
        Self::Crypto(source)
    }
}

/// Why a probe ticket was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TicketRefusal {
    /// The router has no ticket: never issued, or already redeemed.
    #[error("no ticket")]
    Missing,
    /// The ticket is past its expiry.
    #[error("expired")]
    Expired,
    /// The ticket was issued for another SSH port.
    #[error("other port")]
    Port,
    /// The ticket was issued to another actor.
    #[error("other actor")]
    Actor,
    /// The nonce is not the ticket's.
    #[error("other nonce")]
    Nonce,
    /// The confirmed fingerprint is not the probed host key's.
    #[error("other fingerprint")]
    Fingerprint,
}

/// One sealed SSH file: its schema and the sealed plaintext.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    /// Record schema.
    schema: u32,
    /// The sealed plaintext.
    sealed: SealedSecret,
}

/// The sealed parts of a router's SSH state, each with its own associated data.
#[derive(Clone, Copy)]
enum Part {
    /// The enrolment record.
    State,
    /// The private key.
    Key,
    /// The probe ticket.
    Ticket,
}

impl Part {
    /// The file name of this part of `router`.
    fn file_name(self, router: RouterId<'_>) -> String {
        let id = router.as_str();
        match self {
            Self::State => format!("{id}.sealed"),
            Self::Key => format!("{id}.key.sealed"),
            Self::Ticket => format!("{id}.ticket.sealed"),
        }
    }

    /// The associated data of this part of `router`.
    fn binding(self, router: RouterId<'_>) -> Binding {
        match self {
            Self::State => Binding::router_ssh_state(router),
            Self::Key => Binding::router_ssh_key(router),
            Self::Ticket => Binding::router_ssh_ticket(router),
        }
    }
}

/// Checks `router` against the router id rule.
///
/// # Errors
/// [`SshStateError::InvalidRouter`].
fn router_id(router: &str) -> Result<RouterId<'_>, SshStateError> {
    RouterId::parse(router).map_err(|_error| SshStateError::InvalidRouter)
}

/// The owner-only SSH state directory, created when absent.
///
/// # Errors
/// A typed storage failure.
fn directory(state: &StateStore) -> Result<PathBuf, SshStateError> {
    let directory = state.dir().join(SSH_DIR);
    create_private_dir(&directory)?;
    Ok(directory)
}

/// Takes the lock serializing writers of `router`'s SSH files of `scope`.
///
/// # Errors
/// A typed storage failure.
fn lock(state: &StateStore, scope: &str, router: RouterId<'_>) -> Result<StateLock, SshStateError> {
    Ok(state.lock(&format!("{scope}-{}", router.as_str()))?)
}

/// Seals `plaintext` as `part` of `router` and replaces its file; the caller holds the lock.
///
/// # Errors
/// A typed storage or cryptographic failure.
fn write_sealed(
    store: (&StateStore, &MasterKey),
    target: (RouterId<'_>, Part),
    plaintext: &SecretString,
) -> Result<(), SshStateError> {
    let (state, key) = store;
    let (router, part) = target;
    let envelope = Envelope {
        schema: SCHEMA,
        sealed: key.seal(&part.binding(router), plaintext)?,
    };
    let mut bytes = serde_json::to_vec_pretty(&envelope).map_err(|_error| SshStateError::Record)?;
    bytes.push(b'\n');
    write_atomic(&directory(state)?, &part.file_name(router), &bytes)?;
    Ok(())
}

/// Reads the file at `path`, `None` when it does not exist.
///
/// # Errors
/// A typed storage failure.
fn read_file(path: &Path) -> Result<Option<Vec<u8>>, SshStateError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(path, error).into()),
    }
}

/// Opens the sealed `bytes` of `part` of `router`.
///
/// # Errors
/// [`SshStateError::Record`] for another schema or shape, or a cryptographic failure.
fn open_sealed(
    key: &MasterKey,
    target: (RouterId<'_>, Part),
    bytes: &[u8],
) -> Result<SecretString, SshStateError> {
    let (router, part) = target;
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|_error| SshStateError::Record)?;
    if envelope.schema != SCHEMA {
        return Err(SshStateError::Record);
    }
    Ok(key.open(&part.binding(router), &envelope.sealed)?)
}

/// Removes `path`, accepting an absent one.
///
/// # Errors
/// A typed storage failure.
fn remove_if_present(path: &Path) -> Result<(), SshStateError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(path, error).into()),
    }
}
