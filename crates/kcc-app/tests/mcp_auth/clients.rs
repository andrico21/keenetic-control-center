//! The client registry: stored fields, the purge of clients without a grant and kcc's own
//! registration limiter.

extern crate alloc;

use alloc::sync::Arc;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::fs;

use kcc_app::{
    accounts::Clock,
    mcp_auth::clients::{Client, ClientRegistration, REGISTRATIONS_PER_HOUR, RegistrationLimiter},
};
use serde_json::{Value, json};

use super::{Fixture, START, TestResult};

/// todo 30: `mcp_oauth_clients.json` stores the id, name, redirect URIs, registration and
/// last grant times and the pre-registered flag, and nothing else.
#[test]
fn a_client_is_stored_with_its_registration() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/cb")?;
    let admin = fixture.clients.register(
        &ClientRegistration::new(None, vec!["https://kcc.example/cb".to_owned()]).pre_registered(),
    )?;
    drop(fixture.connect(&client, "alice")?);

    let text = fs::read_to_string(fixture.state.dir().join("mcp_oauth_clients.json"))?;
    let stored: Value = serde_json::from_str(&text)?;
    assert_eq!(
        stored,
        json!({"schema": 1_u32, "clients": [
            {"id": client.id(), "name": "Test client", "redirect_uris": ["http://127.0.0.1/cb"],
             "registered_at": START, "last_grant_at": START, "pre_registered": false},
            {"id": admin.id(), "name": null, "redirect_uris": ["https://kcc.example/cb"],
             "registered_at": START, "last_grant_at": null, "pre_registered": true},
        ]})
    );
    assert_eq!(client.id().len(), 64, "256-bit id");
    assert!(client.id().bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_ne!(client.id(), admin.id());
    Ok(())
}

/// todo 30: purge removes a dynamic client without a live grant 24 hours after its
/// registration or last grant; a client with a live grant and a pre-registered one stay.
#[test]
fn purge_removes_only_clients_without_a_live_grant() -> TestResult {
    let fixture = Fixture::new()?;
    let idle = fixture.client("http://127.0.0.1/idle")?;
    let live = fixture.client("http://127.0.0.1/live")?;
    let revoked = fixture.client("http://127.0.0.1/revoked")?;
    let admin = fixture.clients.register(
        &ClientRegistration::new(None, vec!["http://127.0.0.1/admin".to_owned()]).pre_registered(),
    )?;
    drop(fixture.connect(&live, "alice")?);
    let gone = fixture.connect(&revoked, "bob")?;
    assert!(fixture.grants.revoke(gone.grant().id())?);

    fixture.clock.advance(24 * 3600 - 1_u64);
    assert_eq!(fixture.clients.purge()?, 0, "nothing is 24 hours old yet");
    fixture.clock.advance(1);
    assert_eq!(fixture.clients.purge()?, 2);

    let document = fixture.clients.document()?;
    let ids: Vec<&str> = document.clients().iter().map(Client::id).collect();
    assert_eq!(ids, [live.id(), admin.id()]);
    assert!(document.client(idle.id()).is_none());
    assert!(document.client(revoked.id()).is_none());
    Ok(())
}

/// todo 30: kcc's limiter admits 10 registrations per address per hour (an IPv6 /64
/// counts as one address) and keeps no address in state or `Debug`.
#[test]
fn registrations_are_limited_per_address() -> TestResult {
    let fixture = Fixture::new()?;
    let clock: Arc<dyn Clock> = Arc::<super::ManualClock>::clone(&fixture.clock);
    let limiter = RegistrationLimiter::new(clock);
    let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
    let other = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

    assert_eq!(REGISTRATIONS_PER_HOUR, 10);
    for attempt in 0_u32..10 {
        assert!(limiter.admit(address), "registration {attempt} is admitted");
        drop(fixture.client("http://127.0.0.1/cb")?);
    }
    assert!(
        !limiter.admit(address),
        "the 11th within the hour is refused"
    );
    assert!(limiter.admit(other), "another address is admitted");
    fixture.clock.advance(3599);
    assert!(!limiter.admit(address), "still within the hour");
    fixture.clock.advance(1);
    assert!(limiter.admit(address), "an hour after the first");

    let net = Ipv6Addr::new(0x2001, 0x0db8, 1, 2, 0, 0, 0, 0);
    for host in 0..10 {
        assert!(limiter.admit(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db8, 1, 2, 0, 0, 0, host
        ))));
    }
    assert!(!limiter.admit(IpAddr::V6(net)), "one /64 is one address");

    let mut files = String::new();
    for entry in fs::read_dir(fixture.state.dir())? {
        let path = entry?.path();
        if path.is_file() {
            files.push_str(&String::from_utf8_lossy(&fs::read(path)?));
        }
    }
    for needle in ["203.0.113.77", "198.51.100.7", "2001:db8"] {
        assert!(!files.contains(needle), "{needle} is not stored");
        assert!(
            !format!("{limiter:?}").contains(needle),
            "{needle} not in Debug"
        );
    }
    Ok(())
}
