//! The checks every operation runs before it connects, and the pinned key-only session.

use kcc_app::entware_ssh::state::EnrolmentState;
use kcc_ssh::{
    keys::{Auth, HostKeyPin},
    session::Session,
    transport::PinnedTarget,
};

use super::Run;
use crate::{
    RouterCtx,
    entware::ssh::{error::EntwareError, preflight},
};

/// Opens the router's session pinned to the enrolled host key, authenticated with kcc's
/// key, after refusing a missing, Pending or switched-off enrolment, a changed router
/// host and `opkg chroot`.
///
/// # Errors
/// [`EntwareError::NotEnrolled`], [`EntwareError::SshDisabled`],
/// [`EntwareError::RouterHostChanged`], [`EntwareError::ChrootEnabled`], the router read's
/// failure, a state failure, or the connection's SSH failure (a host key mismatch before
/// authentication).
// NOT cancel-safe: the chroot read may sign in first.
pub(super) async fn open(run: &mut Run<'_>, router: &RouterCtx) -> Result<Session, EntwareError> {
    let (services, caller) = (run.services, run.caller);
    let record = preflight::checked_record(services, router, caller)?
        .filter(|record| record.state == EnrolmentState::Active)
        .ok_or(EntwareError::NotEnrolled)?;
    if !record.enabled {
        return Err(EntwareError::SshDisabled);
    }
    preflight::refuse_chroot(router).await?;
    run.facts.port = Some(record.port);
    run.facts.fingerprint.clone_from(&record.fingerprint);
    let pinned = record
        .host_key
        .as_deref()
        .ok_or(EntwareError::NotEnrolled)?;
    let pin = HostKeyPin::from_openssh(pinned)?;
    let key = services
        .store
        .load_key(caller.router)?
        .ok_or(EntwareError::NotEnrolled)?;
    let router_id = preflight::router_id(caller)?;
    let addresses = preflight::admit(services, router, record.port).await?;
    Ok(services
        .pool
        .acquire(&router_id)
        .await?
        .connect(
            PinnedTarget::new(addresses, pin),
            Auth::Key(key),
            services.timeouts,
        )
        .await?)
}
