//! The bootstrap and re-pin steps: ticket, key, Pending pin, key append, liveness check,
//! Active.

use kcc_app::entware_ssh::{state::EnrolmentState, ticket::TicketScope};
use kcc_ssh::{
    command::EntwareCommand,
    error::SshError,
    grammar::PublicKeyLine,
    keys::{Auth, HostKeyPin, generate_ed25519},
    parse,
    session::Output,
    transport::PinnedTarget,
};
use secrecy::ExposeSecret as _;

use super::{Confirmation, Enrolled, Flow};
use crate::{
    RouterCtx,
    entware::ssh::{error::EntwareError, preflight, report::Action},
};

/// Entware's documented default root password.
const DEFAULT_PASSWORD: &str = "keenetic";

/// Enrols the router for the flow's action (bootstrap or re-pin).
///
/// The new key and the Pending enrolment with the pin and router host are saved before
/// the router is contacted, so a failure at any later point leaves a Pending record that
/// a new probe and bootstrap repeat; the marked line replaces any older one. The password
/// is moved into the one password session and dropped (zeroized) with it.
///
/// # Errors
/// As [`super::bootstrap`] and [`super::repin`].
// NOT cancel-safe: dropped mid-way, the enrolment stays Pending (with the key possibly
// installed); a new probe and bootstrap finish it.
pub(super) async fn run(
    flow: &mut Flow<'_>,
    router: &RouterCtx,
    confirmation: Confirmation,
) -> Result<Enrolled, EntwareError> {
    let (services, caller) = (flow.services, flow.caller);
    preflight::authorize_enrolment(caller)?;
    let _lease = services
        .workflow
        .reserve(caller.router, caller.actor, caller.role)?;
    preflight::refuse_chroot(router).await?;
    let mut record = preflight::checked_record(services, router, caller)?.unwrap_or_default();
    flow.facts.port = Some(record.port);
    let Confirmation {
        nonce,
        fingerprint: confirmed,
        password,
    } = confirmation;
    let (host_key, fingerprint) = services.tickets.redeem(
        TicketScope::new(caller.router, record.port, &caller.actor.id),
        &nonce,
        &confirmed,
    )?;
    flow.facts.fingerprint = Some(fingerprint.clone());
    check_pin(flow.facts.action, record.host_key.as_deref(), &host_key)?;
    if flow.facts.action.replaces_pin() {
        flow.facts
            .previous_fingerprint
            .clone_from(&record.fingerprint);
    }
    let pin = HostKeyPin::from_openssh(&host_key)?;
    let router_id = preflight::router_id(caller)?;
    let (private, public) = generate_ed25519()?;
    let line = PublicKeyLine::parse(&public)?;
    services.store.save_key(caller.router, &private)?;
    record.state = EnrolmentState::Pending;
    record.router_host = Some(preflight::current_host(router));
    record.host_key = Some(host_key);
    record.fingerprint = Some(fingerprint.clone());
    services.store.save(caller.router, &record)?;
    let default_password_in_use = password.expose_secret() == DEFAULT_PASSWORD;
    let target = PinnedTarget::new(preflight::admit(services, router, record.port).await?, pin);
    let session = services
        .pool
        .acquire(&router_id)
        .await?
        .connect(target.clone(), Auth::Password(password), services.timeouts)
        .await?;
    succeeded(
        &session
            .run(&EntwareCommand::AppendKey {
                line,
                router_id: router_id.clone(),
            })
            .await?,
    )?;
    drop(session);
    let keyed = services
        .pool
        .acquire(&router_id)
        .await?
        .connect(target, Auth::Key(private), services.timeouts)
        .await?;
    drop(parse::installed(
        &keyed.run(&EntwareCommand::ListInstalled).await?,
    )?);
    drop(keyed);
    record.state = EnrolmentState::Active;
    record.enrolled_at = Some(services.clock.unix_seconds());
    record.enrolled_by = Some(caller.actor.id.clone());
    services.store.save(caller.router, &record)?;
    flow.facts.default_password_in_use = Some(default_password_in_use);
    Ok(Enrolled {
        fingerprint,
        default_password_in_use,
    })
}

/// Checks the probed host key against the pinned one: a bootstrap keeps an existing pin,
/// a re-pin needs a pin to replace and another key.
///
/// # Errors
/// [`EntwareError::RepinRequired`], [`EntwareError::NotEnrolled`] or
/// [`EntwareError::HostKeyUnchanged`].
fn check_pin(action: Action, pinned: Option<&str>, presented: &str) -> Result<(), EntwareError> {
    let changed = pinned.is_some_and(|key| key != presented);
    match (action.replaces_pin(), pinned, changed) {
        (false, _, true) => Err(EntwareError::RepinRequired),
        (false, _, false) | (true, Some(_), true) => Ok(()),
        (true, None, _) => Err(EntwareError::NotEnrolled),
        (true, Some(_), false) => Err(EntwareError::HostKeyUnchanged),
    }
}

/// Whether a key command exited 0.
///
/// # Errors
/// [`SshError::UnexpectedOutput`] for another exit status.
pub(super) const fn succeeded(output: &Output) -> Result<(), SshError> {
    if output.exit_status() == 0 {
        Ok(())
    } else {
        Err(SshError::UnexpectedOutput)
    }
}
