//! A flood of authorization requests cannot evict a legitimate pending one.

use core::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use kcc_app::mcp_auth::pending::{
    AuthorizationRequest, CodeTarget, MAX_ENTRIES, MAX_ENTRIES_PER_SOURCE, REQUEST_LIFETIME_SECONDS,
};
use secrecy::{ExposeSecret as _, SecretString};

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

/// Whether each of `ids` is still pending.
fn alive(fixture: &Fixture, ids: &[SecretString]) -> Vec<bool> {
    ids.iter()
        .map(|id| fixture.pending.peek(id.expose_secret()).is_some())
        .collect()
}

/// `MAX_ENTRIES_PER_SOURCE` liveness flags of which only the oldest is `false`.
fn all_but_the_oldest() -> Vec<bool> {
    (0..MAX_ENTRIES_PER_SOURCE)
        .map(|index| index != 0)
        .collect()
}

/// Opens `count` requests of `request` from `from`, oldest first.
fn open(
    fixture: &Fixture,
    request: &AuthorizationRequest,
    from: IpAddr,
    count: usize,
) -> Result<Vec<SecretString>, Box<dyn Error>> {
    let mut ids = Vec::with_capacity(count);
    for _request in 0..count {
        ids.push(fixture.pending.begin(request.clone(), from)?);
    }
    Ok(ids)
}

/// A request of a fresh client of `fixture`.
fn a_request(fixture: &Fixture) -> Result<AuthorizationRequest, Box<dyn Error>> {
    let client = fixture.client("http://127.0.0.1/cb")?;
    let target = CodeTarget::new(client.id(), "http://127.0.0.1/cb", RESOURCE);
    Ok(AuthorizationRequest::new(
        &client,
        target,
        challenge(&verifier()?)?,
    )?)
}

/// The address `host` of the IPv6 /64 number `block` (in `2001:db8::/32`).
const fn v6(block: u16, host: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, block, 0, 0, 0, host))
}

/// todo 31 (N01): the addresses of one IPv6 /64 are one source, the addresses of other
/// /64s are not, and an IPv4-mapped IPv6 address is its IPv4 address.
#[test]
fn a_source_is_an_ipv4_address_or_an_ipv6_slash_64() -> TestResult {
    let fixture = Fixture::new()?;
    let request = a_request(&fixture)?;
    let mut one_block = Vec::new();
    for host in 1_u16..=40 {
        one_block.push(fixture.pending.begin(request.clone(), v6(1, host))?);
    }
    let kept = one_block.len().saturating_sub(MAX_ENTRIES_PER_SOURCE);
    assert_eq!(
        alive(&fixture, &one_block)
            .iter()
            .filter(|live| **live)
            .count(),
        MAX_ENTRIES_PER_SOURCE,
        "one /64 holds one share"
    );
    assert!(
        alive(&fixture, one_block.get(kept..).ok_or("the newest")?)
            .iter()
            .all(|live| *live),
        "the newest of the /64 stay"
    );

    let other_blocks: Vec<SecretString> = (2_u16..=40)
        .map(|block| fixture.pending.begin(request.clone(), v6(block, 1)))
        .collect::<Result<_, _>>()?;
    assert!(
        alive(&fixture, &other_blocks).iter().all(|live| *live),
        "other /64s are other sources"
    );

    let v4 = Ipv4Addr::new(203, 0, 113, 9);
    let plain = open(&fixture, &request, IpAddr::V4(v4), MAX_ENTRIES_PER_SOURCE)?;
    let mapped = fixture
        .pending
        .begin(request, IpAddr::V6(v4.to_ipv6_mapped()))?;
    assert_eq!(
        alive(&fixture, &plain),
        all_but_the_oldest(),
        "the IPv4-mapped address shares the IPv4 address's share"
    );
    assert!(fixture.pending.peek(mapped.expose_secret()).is_some());
    Ok(())
}

/// todo 31 (N08): a full store makes the OLDEST request of the source holding the most
/// give way: not its newest, not the oldest of the store.
#[test]
fn a_full_store_evicts_the_oldest_request_of_the_largest_source() -> TestResult {
    let fixture = Fixture::new()?;
    let request = a_request(&fixture)?;
    let first = open(
        &fixture,
        &request,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        1,
    )?;
    let singles: Vec<SecretString> = (1_u16..)
        .take(MAX_ENTRIES - 1 - MAX_ENTRIES_PER_SOURCE)
        .map(|block| fixture.pending.begin(request.clone(), v6(block, 1)))
        .collect::<Result<_, _>>()?;
    let largest = open(
        &fixture,
        &request,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        MAX_ENTRIES_PER_SOURCE,
    )?;
    assert!(
        alive(&fixture, &largest).iter().all(|live| *live),
        "the store is exactly full"
    );

    let newcomer = open(
        &fixture,
        &request,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        1,
    )?;
    assert_eq!(
        alive(&fixture, &largest),
        all_but_the_oldest(),
        "only the oldest of the largest source gave way"
    );
    assert!(alive(&fixture, &first).iter().all(|live| *live));
    assert!(alive(&fixture, &singles).iter().all(|live| *live));
    assert!(alive(&fixture, &newcomer).iter().all(|live| *live));
    let debug = format!("{:?}", fixture.pending);
    assert!(
        debug.contains(&format!("requests: {MAX_ENTRIES},")),
        "{debug}"
    );
    Ok(())
}

/// todo 31 (N09): expired requests are dropped when a request begins: they count toward
/// neither the store's bound nor a source's share.
#[test]
fn expired_requests_count_toward_no_cap() -> TestResult {
    let fixture = Fixture::new()?;
    let request = a_request(&fixture)?;
    let old: Vec<SecretString> = (1_u16..)
        .take(MAX_ENTRIES - MAX_ENTRIES_PER_SOURCE)
        .map(|block| fixture.pending.begin(request.clone(), v6(block, 1)))
        .collect::<Result<_, _>>()?;
    let source = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let old_share = open(&fixture, &request, source, MAX_ENTRIES_PER_SOURCE)?;
    fixture.clock.advance(REQUEST_LIFETIME_SECONDS);
    assert!(!alive(&fixture, &old).iter().any(|live| *live));
    assert!(!alive(&fixture, &old_share).iter().any(|live| *live));

    let share = open(&fixture, &request, source, MAX_ENTRIES_PER_SOURCE)?;
    let other = open(
        &fixture,
        &request,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        1,
    )?;
    assert!(
        alive(&fixture, &share).iter().all(|live| *live),
        "expired requests made no live one give way"
    );
    assert!(alive(&fixture, &other).iter().all(|live| *live));
    let debug = format!("{:?}", fixture.pending);
    assert!(
        debug.contains(&format!(
            "requests: {},",
            MAX_ENTRIES_PER_SOURCE.saturating_add(1)
        )),
        "only the live requests are held: {debug}"
    );
    Ok(())
}
