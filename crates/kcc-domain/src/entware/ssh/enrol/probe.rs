//! The probe step: the host key, unauthenticated, and its ticket.

use kcc_app::entware_ssh::{
    state::DEFAULT_PORT,
    ticket::{TICKET_LIFETIME_SECONDS, TicketScope},
};

use super::{Flow, ProbeTicket};
use crate::{
    RouterCtx,
    entware::ssh::{error::EntwareError, preflight},
};

/// Probes the host key on the record's port (222 without a record) and issues the ticket.
///
/// # Errors
/// As [`super::probe`].
// NOT cancel-safe: the chroot read may sign in first; otherwise, dropped, at most an issued
// ticket nobody holds remains.
pub(super) async fn run(
    flow: &mut Flow<'_>,
    router: &RouterCtx,
) -> Result<ProbeTicket, EntwareError> {
    let (services, caller) = (flow.services, flow.caller);
    preflight::authorize_enrolment(caller)?;
    services.audit.require_alive()?;
    preflight::refuse_chroot(router).await?;
    let port = preflight::checked_record(services, router, caller)?
        .map_or(DEFAULT_PORT, |record| record.port);
    flow.facts.port = Some(port);
    let addresses = preflight::admit(services, router, port).await?;
    let pin = services
        .pool
        .acquire(&preflight::router_id(caller)?)
        .await?
        .probe_host_key(&addresses, services.timeouts)
        .await?;
    let fingerprint = pin.fingerprint();
    flow.facts.fingerprint = Some(fingerprint.clone());
    let host_key = pin.to_openssh()?;
    let expires_at = services
        .clock
        .unix_seconds()
        .saturating_add(TICKET_LIFETIME_SECONDS);
    let nonce = services.tickets.issue(
        TicketScope::new(caller.router, port, &caller.actor.id),
        &host_key,
        &fingerprint,
    )?;
    Ok(ProbeTicket {
        nonce,
        fingerprint,
        host_key,
        expires_at,
    })
}
