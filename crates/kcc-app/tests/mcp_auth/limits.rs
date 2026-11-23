//! Registration and grant limits: 5 redirect URIs, 64-character names, 50 clients, 20
//! grants per account and 500 grants in total.

extern crate alloc;

use alloc::sync::Arc;
use core::{
    error::Error,
    net::{IpAddr, Ipv4Addr},
    sync::atomic::AtomicU64,
};
use std::fs;

use kcc_app::{
    accounts::Clock,
    mcp_auth::{
        clients::{ClientError, ClientRegistration, REGISTRATIONS_PER_HOUR, RegistrationLimiter},
        grants::{GrantError, IssuedGrant, MAX_GRANTS, MAX_GRANTS_PER_ACCOUNT},
        pending::{AuthorizationRequest, CodeRefusal, CodeTarget, MAX_ENTRIES},
    },
};
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};

use super::{Fixture, ManualClock, RESOURCE, START, TestResult, challenge, random_text, verifier};

/// The registration of `name` with `count` loopback redirect URIs.
fn registration(name: Option<String>, count: u16) -> ClientRegistration {
    let uris = (1..=count)
        .map(|port| format!("http://127.0.0.1:{port}/cb"))
        .collect();
    ClientRegistration::new(name, uris)
}

/// todo 30: 1 to 5 redirect URIs and a client name of at most 64 characters without
/// control characters.
#[test]
fn registration_fields_are_bounded() -> TestResult {
    let fixture = Fixture::new()?;
    let register =
        |name: Option<String>, count| fixture.clients.register(&registration(name, count));

    let five = register(Some("e".repeat(64)), 5)?;
    assert_eq!(five.redirect_uris().len(), 5);
    assert_eq!(five.name(), Some("e".repeat(64).as_str()));
    assert!(register(None, 1).is_ok(), "the name is optional");
    for (name, count, field) in [
        (None, 0, "redirect_uris"),
        (None, 6, "redirect_uris"),
        (Some("\u{e9}".repeat(65)), 1, "client_name"),
        (Some("line\nbreak".to_owned()), 1, "client_name"),
        (Some(String::new()), 1, "client_name"),
    ] {
        assert!(
            matches!(register(name, count), Err(ClientError::Invalid { field: refused }) if refused == field),
            "{field} with {count} URIs"
        );
    }
    Ok(())
}

/// todo 30: the 51st client is refused until a client without a grant is purged after
/// 24 hours.
#[test]
fn at_most_fifty_clients_are_registered() -> TestResult {
    let fixture = Fixture::new()?;
    for _ in 0_u32..50 {
        drop(fixture.client("http://127.0.0.1/cb")?);
    }
    assert!(matches!(
        fixture.clients.register(&registration(None, 1)),
        Err(ClientError::TooMany)
    ));
    assert_eq!(fixture.clients.document()?.clients().len(), 50);

    fixture.clock.advance(24 * 3600);
    drop(fixture.clients.register(&registration(None, 1))?);
    assert_eq!(
        fixture.clients.document()?.clients().len(),
        1,
        "purged first"
    );
    Ok(())
}

/// todo 30: an account holds at most 20 live grants; a revoked one frees its slot and
/// other accounts are not affected.
#[test]
fn an_account_holds_at_most_twenty_grants() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/cb")?;
    let mut first = None;
    for _ in 0..MAX_GRANTS_PER_ACCOUNT {
        first = first.or(Some(fixture.connect(&client, "alice")?));
    }
    assert_eq!(MAX_GRANTS_PER_ACCOUNT, 20);
    assert!(matches!(
        refusal(fixture.connect(&client, "alice"))?,
        GrantError::AccountLimit
    ));
    drop(fixture.connect(&client, "bob")?);

    let oldest = first.ok_or("a first grant")?;
    assert!(fixture.grants.revoke(oldest.grant().id())?);
    drop(fixture.connect(&client, "alice")?);
    Ok(())
}

/// The refusal of a code flow that must fail.
fn refusal(outcome: Result<IssuedGrant, Box<dyn Error>>) -> Result<GrantError, Box<dyn Error>> {
    match outcome {
        Ok(_issued) => Err("the grant is refused".into()),
        Err(error) => Ok(*error.downcast::<GrantError>()?),
    }
}

/// todo 30: at most 1024 pending requests and 1024 codes are held; the 1025th of each
/// evicts the oldest.
#[test]
fn pending_requests_and_codes_are_bounded() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/cb")?;
    let target = CodeTarget::new(client.id(), "http://127.0.0.1/cb", RESOURCE);
    let verifier = verifier()?;
    let request = AuthorizationRequest::new(&client, target.clone(), challenge(&verifier)?)?;
    assert_eq!(MAX_ENTRIES, 1024);

    let first_request = fixture.pending.begin(request.clone())?;
    let mut newest_request = first_request.clone();
    for _ in 0..MAX_ENTRIES {
        newest_request = fixture.pending.begin(request.clone())?;
    }
    assert!(
        fixture
            .pending
            .peek(first_request.expose_secret())
            .is_none()
    );
    assert!(
        fixture
            .pending
            .peek(newest_request.expose_secret())
            .is_some()
    );

    let first_code = fixture.pending.issue_code(request.clone(), "alice")?;
    let mut newest_code = first_code.clone();
    for _ in 0..MAX_ENTRIES {
        newest_code = fixture.pending.issue_code(request.clone(), "alice")?;
    }
    assert!(matches!(
        fixture.pending.redeem(&first_code, &target, &verifier),
        Err(CodeRefusal::Unknown)
    ));
    drop(fixture.pending.redeem(&newest_code, &target, &verifier)?);
    Ok(())
}

/// todo 30: the registration limiter tracks at most 4096 addresses; a new address beyond
/// that is refused while a tracked one keeps its own hourly budget.
#[test]
fn the_limiter_tracks_at_most_4096_addresses() {
    let clock: Arc<dyn Clock> = Arc::new(ManualClock(AtomicU64::new(START)));
    let limiter = RegistrationLimiter::new(clock);
    let base = Ipv4Addr::new(198, 51, 100, 0).to_bits();
    let address = |index: u32| IpAddr::V4(Ipv4Addr::from_bits(base.wrapping_add(index)));

    let admitted = (0..4100_u32)
        .filter(|&index| limiter.admit(address(index)))
        .count();
    assert_eq!(admitted, 4096);
    assert!(!limiter.admit(address(5000)), "a new address is refused");
    for attempt in 1..REGISTRATIONS_PER_HOUR {
        assert!(limiter.admit(address(0)), "tracked registration {attempt}");
    }
    assert!(!limiter.admit(address(0)), "the tracked address is limited");
}

/// Stored grant `index` of `account` whose refresh token expires at `expires_at`.
fn seeded(
    index: usize,
    (account, client): (&str, &str),
    expires_at: u64,
) -> Result<Value, Box<dyn Error>> {
    Ok(json!({
        "id": format!("{index:064x}"),
        "account": account,
        "client": client,
        "resource": "https://kcc.example/mcp",
        "created_at": START,
        "last_used_at": START,
        "password": "0".repeat(64),
        "revoked": false,
        "refresh": {"current": random_text()?, "expires_at": expires_at, "previous": []},
    }))
}

/// todo 30: at most 500 live grants in total; a grant whose refresh token expired is
/// purged and frees its slot.
#[test]
fn at_most_five_hundred_grants_are_stored() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/cb")?;
    let mut grants = Vec::new();
    for index in 0..MAX_GRANTS.saturating_sub(1) {
        let account = format!("seed-{}", index.div_euclid(20));
        let expires = START
            .saturating_add(10)
            .saturating_add(u64::try_from(index)?);
        grants.push(seeded(index, (&account, client.id()), expires)?);
    }
    let document = json!({"schema": 1_u32, "grants": grants});
    fs::write(
        fixture.state.dir().join("mcp_oauth_grants.json"),
        serde_json::to_vec(&document)?,
    )?;
    assert_eq!(MAX_GRANTS, 500);

    drop(fixture.connect(&client, "alice")?);
    assert!(matches!(
        refusal(fixture.connect(&client, "bob"))?,
        GrantError::TotalLimit
    ));
    fixture.clock.advance(10);
    drop(fixture.connect(&client, "bob")?);
    let stored = fixture.grants.document()?;
    assert_eq!(
        stored.grants().len(),
        MAX_GRANTS,
        "the expired grant was purged"
    );
    Ok(())
}
