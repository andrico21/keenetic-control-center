//! The enrolment lifecycle of a router's Entware for SSH management.
//!
//! An admin probes the host key (nothing is authenticated) and receives a single-use
//! ticket; confirming its fingerprint with the Entware root password bootstraps: kcc
//! generates a key, saves it and the Pending enrolment with the pin, installs the public
//! key with password authentication, checks a key-only session and marks the enrolment
//! Active. A changed host key is re-pinned the same way. Revoke removes kcc's key from the
//! router and then the local state; disable removes only the local state.

mod install;
mod probe;
mod revoke;

use core::fmt;

use kcc_app::entware_ssh::{self, state::SshEnrolment};
use secrecy::SecretString;

use super::{Caller, Facts, SshServices, error::EntwareError, preflight, report::Action};
use crate::RouterCtx;

/// A probed host key and the single-use ticket that lets its fingerprint be confirmed.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProbeTicket {
    /// The ticket nonce (64 hex digits); bootstrap and re-pin redeem it once.
    pub nonce: String,
    /// The host key's SHA-256 fingerprint, `SHA256:<base64>`, for the admin to confirm.
    pub fingerprint: String,
    /// The host key, `ssh-ed25519 <base64>`.
    pub host_key: String,
    /// When the ticket expires, in Unix seconds.
    pub expires_at: u64,
}

impl fmt::Debug for ProbeTicket {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProbeTicket")
            .field("nonce", &"[REDACTED]")
            .field("fingerprint", &self.fingerprint)
            .field("host_key", &self.host_key)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// An admin's confirmation of a probe: the ticket nonce, the fingerprint the admin
/// confirmed and the Entware root password, which is used once and never stored.
pub struct Confirmation {
    /// The ticket nonce.
    nonce: String,
    /// The fingerprint the admin confirmed.
    fingerprint: String,
    /// The Entware root password.
    password: SecretString,
}

impl fmt::Debug for Confirmation {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Confirmation")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl Confirmation {
    /// The confirmation of the ticket `nonce` with `fingerprint` and `password`.
    #[inline]
    #[must_use]
    pub const fn new(nonce: String, fingerprint: String, password: SecretString) -> Self {
        Self {
            nonce,
            fingerprint,
            password,
        }
    }
}

/// A completed bootstrap or re-pin.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Enrolled {
    /// The pinned host key's fingerprint.
    pub fingerprint: String,
    /// The typed password, which signed in, is Entware's default `keenetic`.
    pub default_password_in_use: bool,
}

/// A completed disable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Disabled {
    /// kcc's key stays in the router's `authorized_keys`: disable never contacts it.
    pub entware_key_still_authorized: bool,
}

/// One audited run of a flow.
struct Flow<'flow> {
    /// The services.
    services: &'flow SshServices,
    /// Who runs the flow.
    caller: &'flow Caller<'flow>,
    /// What the audit entry records.
    facts: Facts,
}

impl<'flow> Flow<'flow> {
    /// A run of `action` by `caller`.
    const fn new(
        services: &'flow SshServices,
        caller: &'flow Caller<'flow>,
        action: Action,
    ) -> Self {
        Self {
            services,
            caller,
            facts: Facts::new(action),
        }
    }

    /// Audits `outcome` and returns it.
    ///
    /// # Errors
    /// `outcome`'s error.
    // NOT cancel-safe: the audit entry may be appended after cancellation.
    async fn finish<T>(self, outcome: Result<T, EntwareError>) -> Result<T, EntwareError> {
        self.facts
            .record(self.services, self.caller, outcome.as_ref().err())
            .await;
        outcome
    }
}

/// Probes the router's Entware host key without authenticating and issues a single-use
/// ticket bound to the router, its SSH port and the actor, valid for five minutes.
///
/// # Errors
/// [`EntwareError::PermissionDenied`] and [`EntwareError::McpRefused`] before any request;
/// [`EntwareError::ChrootEnabled`] and [`EntwareError::RouterHostChanged`] before any
/// connection; SSH, state, audit or router read failures.
// NOT cancel-safe: the chroot read may sign in first, and an audit entry may be appended
// after cancellation; otherwise at most an issued ticket nobody holds remains.
#[inline]
pub async fn probe(
    services: &SshServices,
    router: &RouterCtx,
    caller: &Caller<'_>,
) -> Result<ProbeTicket, EntwareError> {
    let mut flow = Flow::new(services, caller, Action::Probe);
    let outcome = Box::pin(probe::run(&mut flow, router)).await;
    flow.finish(outcome).await
}

/// Enrols the router with a confirmed probe and the Entware root password.
///
/// Redeems the probe ticket for `confirmation`, saves a new key and the Pending enrolment
/// with the pin before contacting the router, installs the key with the password, checks
/// a key-only session, and marks the enrolment Active. A retry from Pending repeats the
/// same steps; kcc's marked line replaces any older one.
///
/// # Errors
/// As [`probe`], plus ticket refusals ([`EntwareError::State`]) and
/// [`EntwareError::RepinRequired`] before any password is sent, and
/// [`kcc_ssh::error::SshError::HostKeyMismatch`] before authentication.
// NOT cancel-safe: dropped mid-way, the enrolment stays Pending (with the key possibly
// installed); a new probe and bootstrap finish it.
#[inline]
pub async fn bootstrap(
    services: &SshServices,
    router: &RouterCtx,
    caller: &Caller<'_>,
    confirmation: Confirmation,
) -> Result<Enrolled, EntwareError> {
    let mut flow = Flow::new(services, caller, Action::Bootstrap);
    let outcome = Box::pin(install::run(&mut flow, router, confirmation)).await;
    flow.finish(outcome).await
}

/// Enrols a router whose Entware host key changed: as [`bootstrap`], but the probed key
/// must differ from the pinned one.
///
/// # Errors
/// As [`bootstrap`], with [`EntwareError::NotEnrolled`] when nothing is pinned and
/// [`EntwareError::HostKeyUnchanged`] for the pinned key, both before any password is sent.
// NOT cancel-safe: dropped mid-way, the enrolment stays Pending with the new pin; a new
// probe and bootstrap finish it.
#[inline]
pub async fn repin(
    services: &SshServices,
    router: &RouterCtx,
    caller: &Caller<'_>,
    confirmation: Confirmation,
) -> Result<Enrolled, EntwareError> {
    let mut flow = Flow::new(services, caller, Action::Repin);
    let outcome = Box::pin(install::run(&mut flow, router, confirmation)).await;
    flow.finish(outcome).await
}

/// Removes kcc's key from the router over a key-only session, then the local record and
/// key.
///
/// # Errors
/// As [`probe`], [`EntwareError::NotEnrolled`] without a pin or key,
/// [`EntwareError::RevokeUnreachable`] when the router cannot be read over RCI, and
/// [`EntwareError::RevokeFailed`] when it cannot be reached over SSH or refuses: the local
/// state is kept, and [`disable`] forgets it locally.
// NOT cancel-safe: dropped after the removal, the line is gone but the record stays; a new
// revoke or a disable finishes.
#[inline]
pub async fn revoke(
    services: &SshServices,
    router: &RouterCtx,
    caller: &Caller<'_>,
) -> Result<(), EntwareError> {
    let mut flow = Flow::new(services, caller, Action::Revoke);
    let outcome = Box::pin(revoke::run(&mut flow, router)).await;
    flow.finish(outcome).await
}

/// Forgets the router's SSH state locally without contacting the router: kcc's key stays
/// authorized there.
///
/// # Errors
/// [`EntwareError::PermissionDenied`], a busy router write lease
/// ([`EntwareError::Workflow`]) or a state failure.
// NOT cancel-safe: the audit entry may be appended after cancellation.
#[inline]
pub async fn disable(
    services: &SshServices,
    caller: &Caller<'_>,
) -> Result<Disabled, EntwareError> {
    let mut flow = Flow::new(services, caller, Action::Disable);
    let outcome = local(caller, services, || {
        entware_ssh::state::forget(services.workflow.state(), caller.router)
    });
    if outcome.is_ok() {
        flow.facts.entware_key_still_authorized = Some(true);
    }
    flow.finish(outcome.map(|()| Disabled {
        entware_key_still_authorized: true,
    }))
    .await
}

/// Sets the router's SSH port (1..=65535), locally.
///
/// # Errors
/// [`EntwareError::PermissionDenied`], a busy router write lease, port 0
/// ([`EntwareError::State`]) or a state failure.
// cancel-safe: it has no await point.
#[expect(
    clippy::unused_async,
    reason = "the enrolment API is async throughout; surfaces await every step alike"
)]
#[inline]
pub async fn set_port(
    services: &SshServices,
    caller: &Caller<'_>,
    port: u16,
) -> Result<SshEnrolment, EntwareError> {
    local(caller, services, || {
        services.store.set_port(caller.router, port)
    })
}

/// Switches SSH management of the router on or off, locally; the pin and state stay.
///
/// # Errors
/// [`EntwareError::PermissionDenied`], a busy router write lease or a state failure.
// cancel-safe: it has no await point.
#[expect(
    clippy::unused_async,
    reason = "the enrolment API is async throughout; surfaces await every step alike"
)]
#[inline]
pub async fn set_enabled(
    services: &SshServices,
    caller: &Caller<'_>,
    enabled: bool,
) -> Result<SshEnrolment, EntwareError> {
    local(caller, services, || {
        services.store.set_enabled(caller.router, enabled)
    })
}

/// Runs the local `change` after the permission check, under the router write lease.
///
/// # Errors
/// [`EntwareError::PermissionDenied`], a busy lease, or `change`'s failure.
fn local<T, F>(caller: &Caller<'_>, services: &SshServices, change: F) -> Result<T, EntwareError>
where
    F: FnOnce() -> Result<T, entware_ssh::SshStateError>,
{
    preflight::authorize(caller)?;
    let _lease = services
        .workflow
        .reserve(caller.router, caller.actor, caller.role)?;
    Ok(change()?)
}
