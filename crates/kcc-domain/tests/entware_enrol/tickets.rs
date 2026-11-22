//! Probe tickets: every refusal happens before a password reaches the router.

use kcc_app::entware_ssh::{SshStateError, TicketRefusal, ticket::TICKET_LIFETIME_SECONDS};
use kcc_domain::entware::ssh::{Caller, enrol, error::EntwareError};
use kcc_ssh::keys::{HostKeyPin, generate_ed25519};
use kcc_testkit::entware_ssh::DEFAULT_PASSWORD;
use secrecy::SecretString;
use tokio::time::timeout;

use crate::{
    harness::{Harness, LIMIT, ROUTER, actor, confirm},
    support::TestResult,
};

/// Whether `result` is the ticket refusal `expected`.
fn refused<T>(result: &Result<T, EntwareError>, expected: TicketRefusal) -> bool {
    matches!(
        result,
        Err(EntwareError::State(SshStateError::Ticket(refusal))) if *refusal == expected
    )
}

/// Todo 9: a nonce used once is refused the second time, with no new connection and no
/// password attempt.
#[tokio::test]
async fn a_reused_nonce_is_refused_without_a_password_attempt() -> TestResult {
    let harness = Harness::default_start().await?;
    let ticket = harness.probe().await?;
    drop(harness.bootstrap_with(&ticket, DEFAULT_PASSWORD).await??);
    let before = harness.counters()?;
    let again = harness.bootstrap_with(&ticket, DEFAULT_PASSWORD).await?;
    assert!(refused(&again, TicketRefusal::Missing), "{again:?}");
    assert_eq!(harness.counters()?, before);
    Ok(())
}

/// Todo 9: a ticket past its five minutes is refused with zero password attempts.
#[tokio::test]
async fn an_expired_ticket_is_refused() -> TestResult {
    let harness = Harness::default_start().await?;
    let ticket = harness.probe().await?;
    harness.clock().advance(TICKET_LIFETIME_SECONDS);
    let outcome = harness.bootstrap_with(&ticket, DEFAULT_PASSWORD).await?;
    assert!(refused(&outcome, TicketRefusal::Expired), "{outcome:?}");
    assert_eq!(harness.counters()?.auth_attempts, 0);
    assert_eq!(harness.record()?.map(|record| record.host_key), Some(None));
    Ok(())
}

/// Todo 9: a ticket probed by `alice` is refused to `bob`, with zero password attempts.
#[tokio::test]
async fn a_ticket_of_another_actor_is_refused() -> TestResult {
    let harness = Harness::default_start().await?;
    let ticket = harness.probe().await?;
    let bob = actor("bob");
    let caller = Caller::new(ROUTER, &bob, harness.admin());
    let outcome = timeout(
        LIMIT,
        enrol::bootstrap(
            harness.services(),
            harness.context(),
            &caller,
            confirm(&ticket, DEFAULT_PASSWORD),
        ),
    )
    .await?;
    assert!(refused(&outcome, TicketRefusal::Actor), "{outcome:?}");
    assert_eq!(harness.counters()?.auth_attempts, 0);
    Ok(())
}

/// Todo 9: a ticket probed on one SSH port is refused once the router's port changed,
/// with zero password attempts.
#[tokio::test]
async fn a_ticket_of_another_port_is_refused() -> TestResult {
    let harness = Harness::default_start().await?;
    let ticket = harness.probe().await?;
    let port = harness.ssh_address()?.port();
    drop(harness.set_port(port.wrapping_add(1).max(1)).await?);
    let outcome = harness.bootstrap_with(&ticket, DEFAULT_PASSWORD).await?;
    assert!(refused(&outcome, TicketRefusal::Port), "{outcome:?}");
    assert_eq!(harness.counters()?.auth_attempts, 0);
    Ok(())
}

/// Todo 9: a confirmed fingerprint other than the probed one is refused with one
/// connection (the probe's) and zero password attempts.
#[tokio::test]
async fn another_confirmed_fingerprint_is_refused() -> TestResult {
    let harness = Harness::default_start().await?;
    let mut ticket = harness.probe().await?;
    let (_private, line) = generate_ed25519()?;
    ticket.fingerprint = HostKeyPin::from_openssh(&line)?.fingerprint();
    let outcome = harness.bootstrap_with(&ticket, DEFAULT_PASSWORD).await?;
    assert!(refused(&outcome, TicketRefusal::Fingerprint), "{outcome:?}");
    let counters = harness.counters()?;
    assert_eq!((counters.connections, counters.auth_attempts), (1, 0));
    Ok(())
}

/// Todo 9: another nonce is refused with zero password attempts.
#[tokio::test]
async fn another_nonce_is_refused() -> TestResult {
    let harness = Harness::default_start().await?;
    let mut ticket = harness.probe().await?;
    ticket.nonce = "0".repeat(64);
    let outcome = timeout(
        LIMIT,
        enrol::bootstrap(
            harness.services(),
            harness.context(),
            &harness.caller(),
            enrol::Confirmation::new(
                ticket.nonce.clone(),
                ticket.fingerprint.clone(),
                SecretString::from(DEFAULT_PASSWORD),
            ),
        ),
    )
    .await?;
    assert!(refused(&outcome, TicketRefusal::Nonce), "{outcome:?}");
    assert_eq!(harness.counters()?.auth_attempts, 0);
    Ok(())
}
