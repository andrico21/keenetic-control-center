//! Single-use probe tickets: the host key a probe saw, handed to the bootstrap that confirms
//! its fingerprint.

extern crate alloc;

use alloc::sync::Arc;
use core::fmt::{self, Write as _};
use std::{fs, io};

use chacha20poly1305::aead::Generate as _;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use super::{
    Part, SshStateError, TicketRefusal, directory, lock, open_sealed, remove_if_present, router_id,
    state::TICKET_LOCK_SCOPE, write_sealed,
};
use crate::{
    accounts::Clock,
    persist::{StateStore, io_error},
    secrets::{CryptoError, MasterKey},
};

/// How long a ticket stays redeemable after it was issued, in seconds.
pub const TICKET_LIFETIME_SECONDS: u64 = 300;
/// Random bytes in a nonce (256 bits).
const NONCE_BYTES: usize = 32;

/// What a ticket is bound to: the router, the SSH port and the actor.
#[expect(
    clippy::module_name_repetitions,
    reason = "the name the enrolment flow uses for the ticket binding"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TicketScope<'scope> {
    /// Router id.
    pub router: &'scope str,
    /// SSH port the host key was probed on.
    pub port: u16,
    /// The acting principal.
    pub actor: &'scope str,
}

impl<'scope> TicketScope<'scope> {
    /// The scope of `actor` probing `router` on `port`.
    #[inline]
    #[must_use]
    pub const fn new(router: &'scope str, port: u16, actor: &'scope str) -> Self {
        Self {
            router,
            port,
            actor,
        }
    }
}

/// The sealed content of one ticket.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ticket {
    /// The random nonce the redeemer must present.
    nonce: String,
    /// The probed host key's fingerprint, `SHA256:<base64>`.
    fingerprint: String,
    /// The probed host key, `ssh-ed25519 <base64>`.
    host_key: String,
    /// SSH port of the probe.
    port: u16,
    /// Actor of the probe.
    actor: String,
    /// Expiry in Unix seconds; redeemable strictly before it.
    expires_at: u64,
}

/// Probe tickets at `<state>/router-ssh/<id>.ticket.sealed`, one per router.
#[expect(
    clippy::module_name_repetitions,
    reason = "the store name the enrolment flow uses"
)]
pub struct TicketStore {
    /// State root holding `router-ssh/` and the locks.
    state: StateStore,
    /// Master key sealing the tickets.
    key: MasterKey,
    /// Clock of issue and expiry.
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for TicketStore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TicketStore")
            .field("state", &self.state)
            .field("key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl TicketStore {
    /// A store rooted in `state`, sealed with `key`, on `clock`.
    #[inline]
    #[must_use]
    pub fn new(state: StateStore, key: MasterKey, clock: Arc<dyn Clock>) -> Self {
        Self { state, key, clock }
    }

    /// Issues a ticket for `host_key` (with `fingerprint`) in `scope`, replacing any older
    /// ticket of the router, and returns its nonce (64 hex digits from the OS RNG).
    ///
    /// # Errors
    /// [`SshStateError::InvalidRouter`], [`SshStateError::InvalidPort`] for port 0, or a
    /// storage, RNG or cryptographic failure.
    #[inline]
    pub fn issue(
        &self,
        scope: TicketScope<'_>,
        host_key: &str,
        fingerprint: &str,
    ) -> Result<String, SshStateError> {
        let id = router_id(scope.router)?;
        if scope.port == 0 {
            return Err(SshStateError::InvalidPort);
        }
        let nonce = random_hex::<NONCE_BYTES>()?;
        let ticket = Ticket {
            nonce: nonce.clone(),
            fingerprint: fingerprint.to_owned(),
            host_key: host_key.to_owned(),
            port: scope.port,
            actor: scope.actor.to_owned(),
            expires_at: self
                .clock
                .unix_seconds()
                .saturating_add(TICKET_LIFETIME_SECONDS),
        };
        let text = serde_json::to_string(&ticket).map_err(|_error| SshStateError::Record)?;
        let _lock = lock(&self.state, TICKET_LOCK_SCOPE, id)?;
        write_sealed(
            (&self.state, &self.key),
            (id, Part::Ticket),
            &SecretString::from(text),
        )?;
        Ok(nonce)
    }

    /// Redeems the router's ticket and returns its `(host_key, fingerprint)`.
    ///
    /// Every attempt consumes the ticket, refused ones included: it is renamed to
    /// `<id>.ticket.redeem.<random>` (one of two concurrent attempts wins the rename), read
    /// and deleted before it is checked.
    ///
    /// # Errors
    /// [`SshStateError::Ticket`] with the refusal, [`SshStateError::InvalidRouter`],
    /// [`SshStateError::Crypto`] for a file sealed for another record, or a storage failure.
    #[inline]
    pub fn redeem(
        &self,
        scope: TicketScope<'_>,
        nonce: &str,
        confirmed_fingerprint: &str,
    ) -> Result<(String, String), SshStateError> {
        let id = router_id(scope.router)?;
        let directory = directory(&self.state)?;
        let ticket_path = directory.join(Part::Ticket.file_name(id));
        let claimed = directory.join(format!(
            "{}.ticket.redeem.{}",
            id.as_str(),
            random_hex::<8>()?
        ));
        let lock = lock(&self.state, TICKET_LOCK_SCOPE, id)?;
        match fs::rename(&ticket_path, &claimed) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(SshStateError::Ticket(TicketRefusal::Missing));
            }
            Err(error) => return Err(io_error(&ticket_path, error).into()),
        }
        drop(lock);
        let read = fs::read(&claimed).map_err(|error| io_error(&claimed, error));
        remove_if_present(&claimed)?;
        let text = open_sealed(&self.key, (id, Part::Ticket), &read?)?;
        let ticket: Ticket =
            serde_json::from_str(text.expose_secret()).map_err(|_error| SshStateError::Record)?;
        check(
            &ticket,
            (scope, self.clock.unix_seconds()),
            nonce,
            confirmed_fingerprint,
        )
        .map_err(SshStateError::Ticket)?;
        Ok((ticket.host_key, ticket.fingerprint))
    }
}

/// Checks `ticket` against the redeemer's scope at `now`, its nonce and fingerprint.
///
/// # Errors
/// The first refusal, in the order expiry, port, actor, nonce, fingerprint.
fn check(
    ticket: &Ticket,
    (scope, now): (TicketScope<'_>, u64),
    nonce: &str,
    confirmed_fingerprint: &str,
) -> Result<(), TicketRefusal> {
    if now >= ticket.expires_at {
        return Err(TicketRefusal::Expired);
    }
    if ticket.port != scope.port {
        return Err(TicketRefusal::Port);
    }
    if ticket.actor != scope.actor {
        return Err(TicketRefusal::Actor);
    }
    if !bool::from(ticket.nonce.as_bytes().ct_eq(nonce.as_bytes())) {
        return Err(TicketRefusal::Nonce);
    }
    if ticket.fingerprint != confirmed_fingerprint {
        return Err(TicketRefusal::Fingerprint);
    }
    Ok(())
}

/// `N` bytes from the OS RNG as lowercase hex.
///
/// # Errors
/// [`SshStateError::Crypto`] when the OS RNG fails.
fn random_hex<const N: usize>() -> Result<String, SshStateError> {
    let bytes = <[u8; N]>::try_generate().map_err(|error| CryptoError::Rng {
        reason: error.to_string(),
    })?;
    let mut text = String::with_capacity(N.saturating_mul(2));
    for byte in bytes {
        write!(text, "{byte:02x}").map_err(|_error| SshStateError::Record)?;
    }
    Ok(text)
}
