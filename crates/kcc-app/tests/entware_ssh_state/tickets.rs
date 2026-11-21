//! Single-use probe tickets (todo 8).

use alloc::sync::Arc;
use core::{error::Error, sync::atomic::Ordering};
use std::{sync::Barrier, thread};

use kcc_app::entware_ssh::{
    SshStateError, TicketRefusal,
    ticket::{TICKET_LIFETIME_SECONDS, TicketScope},
};

use super::{TestResult, World};

/// The host key and fingerprint the probe saw, built at run time.
fn probed() -> (String, String) {
    (
        format!("ssh-ed25519 {}", "C".repeat(68)),
        format!("SHA256:{}", "d".repeat(43)),
    )
}

/// The scope every ticket below is issued in.
const ISSUED: TicketScope<'static> = TicketScope::new("a", 222, "admin");

/// Issues a ticket in [`ISSUED`] and returns its nonce.
fn issue(world: &World) -> Result<String, Box<dyn Error>> {
    let (host_key, fingerprint) = probed();
    Ok(world.tickets.issue(ISSUED, &host_key, &fingerprint)?)
}

/// The refusal of redeeming in `scope` with `nonce` and `fingerprint`.
fn refusal(
    world: &World,
    scope: TicketScope<'_>,
    nonce: &str,
    fingerprint: &str,
) -> Option<TicketRefusal> {
    match world.tickets.redeem(scope, nonce, fingerprint) {
        Err(SshStateError::Ticket(refusal)) => Some(refusal),
        Ok(_) | Err(_) => None,
    }
}

/// Todo 8: a ticket redeems once, in its scope, with its nonce and fingerprint, and leaves
/// no file behind.
#[test]
fn a_ticket_redeems_once() -> TestResult {
    let world = World::new()?;
    let nonce = issue(&world)?;
    let (host_key, fingerprint) = probed();

    let redeemed = world.tickets.redeem(ISSUED, &nonce, &fingerprint)?;

    assert_eq!(redeemed, (host_key, fingerprint.clone()));
    assert_eq!(world.names()?, Vec::<String>::new());
    assert_eq!(
        refusal(&world, ISSUED, &nonce, &fingerprint),
        Some(TicketRefusal::Missing)
    );
    Ok(())
}

/// Todo 8: each mismatch is refused for its own reason, and the refused attempt consumes
/// the ticket.
#[test]
fn every_mismatch_is_refused_and_consumes_the_ticket() -> TestResult {
    let world = World::new()?;
    let (_, fingerprint) = probed();
    let cases = [
        (
            TicketScope::new("a", 2222, "admin"),
            None,
            None,
            TicketRefusal::Port,
        ),
        (
            TicketScope::new("a", 222, "other"),
            None,
            None,
            TicketRefusal::Actor,
        ),
        (ISSUED, Some("0".repeat(64)), None, TicketRefusal::Nonce),
        (
            ISSUED,
            None,
            Some("SHA256:other"),
            TicketRefusal::Fingerprint,
        ),
        (
            TicketScope::new("b", 222, "admin"),
            None,
            None,
            TicketRefusal::Missing,
        ),
    ];
    for (scope, other_nonce, other_fingerprint, expected) in cases {
        let issued = issue(&world)?;
        let presented = other_nonce.unwrap_or_else(|| issued.clone());
        let confirmed = other_fingerprint.unwrap_or(&fingerprint);

        assert_eq!(
            refusal(&world, scope, &presented, confirmed),
            Some(expected),
            "{scope:?}"
        );
        let after = refusal(&world, ISSUED, &issued, &fingerprint);
        if expected == TicketRefusal::Missing {
            assert_eq!(after, None, "another router's attempt leaves a's ticket");
        } else {
            assert_eq!(
                after,
                Some(TicketRefusal::Missing),
                "{expected:?} consumed it"
            );
        }
    }
    Ok(())
}

/// Todo 8: a ticket expires five minutes after it was issued.
#[test]
fn a_ticket_expires_after_five_minutes() -> TestResult {
    let world = World::new()?;
    let (_, fingerprint) = probed();
    let start = world.clock.0.load(Ordering::SeqCst);

    let nonce = issue(&world)?;
    world
        .clock
        .0
        .store(start + TICKET_LIFETIME_SECONDS - 1, Ordering::SeqCst);
    drop(world.tickets.redeem(ISSUED, &nonce, &fingerprint)?);

    world.clock.0.store(start, Ordering::SeqCst);
    let later = issue(&world)?;
    world
        .clock
        .0
        .store(start + TICKET_LIFETIME_SECONDS, Ordering::SeqCst);
    assert_eq!(
        refusal(&world, ISSUED, &later, &fingerprint),
        Some(TicketRefusal::Expired)
    );
    assert_eq!(TICKET_LIFETIME_SECONDS, 300);
    Ok(())
}

/// Todo 8: nonces are 256 random bits in hex, fresh per issue; a new issue replaces the
/// older ticket.
#[test]
fn nonces_are_long_random_and_replace_older_tickets() -> TestResult {
    let world = World::new()?;
    let (_, fingerprint) = probed();

    let first = issue(&world)?;
    let second = issue(&world)?;

    assert_ne!(first, second);
    for nonce in [&first, &second] {
        assert_eq!(nonce.len(), 64, "{nonce}");
        assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
    assert_eq!(
        refusal(&world, ISSUED, &first, &fingerprint),
        Some(TicketRefusal::Nonce)
    );
    let third = issue(&world)?;
    drop(world.tickets.redeem(ISSUED, &third, &fingerprint)?);
    Ok(())
}

/// Todo 8: of two concurrent redeems of one ticket, from two stores as two processes would
/// open them, exactly one succeeds; repeated 50 times.
#[test]
fn two_concurrent_redeems_one_wins() -> TestResult {
    let world = World::new()?;
    let second = Arc::new(world.second_tickets());
    let (_, fingerprint) = probed();
    for _ in 0_u32..50 {
        let nonce = issue(&world)?;
        let barrier = Arc::new(Barrier::new(2));
        let (racer_barrier, racer_store) = (Arc::clone(&barrier), Arc::clone(&second));
        let (racer_nonce, racer_fingerprint) = (nonce.clone(), fingerprint.clone());
        let racer = thread::spawn(move || {
            let _wait = racer_barrier.wait();
            racer_store
                .redeem(ISSUED, &racer_nonce, &racer_fingerprint)
                .is_ok()
        });
        let _wait = barrier.wait();
        let mine = world.tickets.redeem(ISSUED, &nonce, &fingerprint).is_ok();
        let theirs = racer.join().map_err(|_panic| "racer panicked")?;

        assert!(mine ^ theirs, "exactly one wins: {mine} {theirs}");
        assert_eq!(world.names()?, Vec::<String>::new());
    }
    Ok(())
}
