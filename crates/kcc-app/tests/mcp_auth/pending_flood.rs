//! A flood of authorization requests cannot evict a legitimate pending one.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use kcc_app::mcp_auth::pending::{
    AuthorizationRequest, CodeTarget, MAX_ENTRIES, MAX_ENTRIES_PER_SOURCE,
};
use secrecy::ExposeSecret as _;

use super::{Fixture, RESOURCE, TestResult, challenge, verifier};

/// todo 31 (N5): a request opened first survives 1000 addresses sending 5 requests each,
/// then one address sending 5000.
///
/// That one address holds at most [`MAX_ENTRIES_PER_SOURCE`] requests (fewer while
/// others hold fewer), the store never holds more than [`MAX_ENTRIES`], and the first
/// request can still be taken (approved).
#[test]
fn a_flood_from_many_addresses_keeps_a_legitimate_request() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/cb")?;
    let target = CodeTarget::new(client.id(), "http://127.0.0.1/cb", RESOURCE);
    let request = AuthorizationRequest::new(&client, target, challenge(&verifier()?)?)?;
    let legit = fixture
        .pending
        .begin(request.clone(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))?;
    for block in 0_u16..1000 {
        let from = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, block, 0, 0, 0, 0, 1));
        for _request in 0_u8..5 {
            drop(fixture.pending.begin(request.clone(), from)?);
        }
    }
    let one = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let mut flood = Vec::new();
    for _request in 0_u16..5000 {
        flood.push(fixture.pending.begin(request.clone(), one)?);
    }
    assert!(
        fixture.pending.peek(legit.expose_secret()).is_some(),
        "the first request survives"
    );
    let held = flood
        .iter()
        .filter(|id| fixture.pending.peek(id.expose_secret()).is_some())
        .count();
    assert!(
        (1..=MAX_ENTRIES_PER_SOURCE).contains(&held),
        "one address holds at most its share: {held}"
    );
    let debug = format!("{:?}", fixture.pending);
    assert!(
        debug.contains(&format!("requests: {MAX_ENTRIES},")),
        "the store is bounded: {debug}"
    );
    assert!(fixture.pending.take(legit.expose_secret()).is_some());
    Ok(())
}

/// todo 31 (N5): one address holds at most [`MAX_ENTRIES_PER_SOURCE`] requests even while
/// the store has room: its 17th request makes its oldest give way.
#[test]
fn one_address_holds_at_most_its_share() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/cb")?;
    let target = CodeTarget::new(client.id(), "http://127.0.0.1/cb", RESOURCE);
    let request = AuthorizationRequest::new(&client, target, challenge(&verifier()?)?)?;
    let one = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let mut opened = Vec::new();
    for _request in 0_u8..40 {
        opened.push(fixture.pending.begin(request.clone(), one)?);
    }
    let live: Vec<bool> = opened
        .iter()
        .map(|id| fixture.pending.peek(id.expose_secret()).is_some())
        .collect();
    let kept = opened.len().saturating_sub(MAX_ENTRIES_PER_SOURCE);
    assert!(
        live.get(kept..)
            .is_some_and(|newest| newest.iter().all(|alive| *alive)),
        "the newest stay: {live:?}"
    );
    assert!(
        live.get(..kept)
            .is_some_and(|oldest| !oldest.iter().any(|alive| *alive)),
        "the oldest gave way: {live:?}"
    );
    Ok(())
}
