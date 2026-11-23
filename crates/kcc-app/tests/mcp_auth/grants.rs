//! Refresh grants: rotation, reuse detection revoking the family, client and resource
//! binding, expiry, and the per-call grant check against the password fingerprint.

use std::fs;

use kcc_app::{
    accounts::standing::PasswordFingerprint,
    mcp_auth::{
        grants::{GrantError, GrantsDocument, IssuedGrant, RefreshRequest},
        verify::{GrantRefusal, check_grant},
    },
};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};

use super::{Fixture, REFRESH_TTL, RESOURCE, START, TestResult, password};

/// Refreshes `token` for `client` as the live accounts of `fixture` allow.
fn refresh(
    fixture: &Fixture,
    token: &SecretString,
    (client, resource): (&str, Option<&str>),
) -> Result<IssuedGrant, GrantError> {
    let standing = |account: &str| -> Option<PasswordFingerprint> {
        fixture.accounts.fingerprint(account).ok().flatten()
    };
    fixture
        .grants
        .refresh(&RefreshRequest::new(token, client, resource), &standing)
}

/// todo 30: a refresh rotates the token; presenting the old one again is reuse and revokes
/// the whole family, the newest token included.
#[test]
fn reuse_of_a_rotated_refresh_token_revokes_the_family() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/cb")?;
    let first = fixture.connect(&client, "alice")?;
    fixture.clock.advance(30);

    let second = refresh(&fixture, first.refresh_token(), (client.id(), None))?;
    assert_eq!(second.grant().id(), first.grant().id(), "same family");
    assert_ne!(
        second.refresh_token().expose_secret(),
        first.refresh_token().expose_secret()
    );
    assert_eq!(second.grant().last_used_at(), START.saturating_add(30));
    let third = refresh(&fixture, second.refresh_token(), (client.id(), None))?;

    assert!(matches!(
        refresh(&fixture, first.refresh_token(), (client.id(), None)),
        Err(GrantError::Reused)
    ));
    assert!(matches!(
        refresh(&fixture, third.refresh_token(), (client.id(), None)),
        Err(GrantError::Revoked)
    ));
    let document = fixture.grants.document()?;
    let fingerprint = fixture.fingerprint("alice")?;
    assert_eq!(
        check_grant(&document, first.grant().id(), "alice", &fingerprint),
        Err(GrantRefusal::Revoked)
    );
    Ok(())
}

/// todo 30: a refresh token is good until its expiry (exclusive), for its own client and
/// resource only; a refused attempt leaves it usable.
#[test]
fn a_refresh_token_is_bound_and_expires() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/cb")?;
    let other = fixture.client("http://127.0.0.1/cb")?;
    let issued = fixture.connect(&client, "alice")?;
    let token = issued.refresh_token();

    assert!(matches!(
        refresh(&fixture, token, (other.id(), None)),
        Err(GrantError::Client)
    ));
    let elsewhere = Some("https://kcc.example/other");
    assert!(matches!(
        refresh(&fixture, token, (client.id(), elsewhere)),
        Err(GrantError::Resource)
    ));
    let unknown = SecretString::from("x".repeat(43));
    assert!(matches!(
        refresh(&fixture, &unknown, (client.id(), None)),
        Err(GrantError::Unknown)
    ));

    fixture
        .clock
        .advance(REFRESH_TTL.as_secs().saturating_sub(1));
    let renewed = refresh(&fixture, token, (client.id(), Some(RESOURCE)))?;
    assert_eq!(
        renewed.grant().refresh_expires_at(),
        START
            .saturating_add(REFRESH_TTL.as_secs().saturating_mul(2))
            .saturating_sub(1),
        "a rotation starts a new lifetime"
    );
    fixture.clock.advance(REFRESH_TTL.as_secs());
    assert!(matches!(
        refresh(&fixture, renewed.refresh_token(), (client.id(), None)),
        Err(GrantError::Expired)
    ));
    Ok(())
}

/// todo 30: a password change invalidates the account's grants for calls and refreshes; a
/// disabled account (no standing) refreshes nothing; other accounts keep theirs.
#[test]
fn a_password_change_invalidates_the_grant() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/cb")?;
    let alice = fixture.connect(&client, "alice")?;
    let bob = fixture.connect(&client, "bob")?;
    let before = fixture.fingerprint("alice")?;
    let document = fixture.grants.document()?;
    assert_eq!(
        check_grant(&document, alice.grant().id(), "alice", &before),
        Ok(())
    );
    assert_eq!(
        check_grant(
            &document,
            alice.grant().id(),
            "bob",
            &fixture.fingerprint("bob")?
        ),
        Err(GrantRefusal::Account)
    );
    assert_eq!(
        check_grant(&document, &"0".repeat(64), "alice", &before),
        Err(GrantRefusal::Unknown)
    );

    let _changed = fixture.accounts.change_password(
        "alice",
        &password("alice"),
        &password("alice-renewed"),
    )?;
    let after = fixture.fingerprint("alice")?;
    assert_ne!(after, before);
    assert_eq!(
        check_grant(&document, alice.grant().id(), "alice", &after),
        Err(GrantRefusal::Password)
    );
    assert!(matches!(
        refresh(&fixture, alice.refresh_token(), (client.id(), None)),
        Err(GrantError::Account)
    ));
    let disabled = |_account: &str| -> Option<PasswordFingerprint> { None };
    let request = RefreshRequest::new(bob.refresh_token(), client.id(), None);
    assert!(matches!(
        fixture.grants.refresh(&request, &disabled),
        Err(GrantError::Account)
    ));
    drop(refresh(&fixture, bob.refresh_token(), (client.id(), None))?);
    Ok(())
}

/// todo 30: revocation by a refresh token (RFC 7009) needs the token's own client and
/// revokes the family; by id it is the admin's revocation.
#[test]
fn revocation_ends_the_family() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/cb")?;
    let other = fixture.client("http://127.0.0.1/cb")?;
    let issued = fixture.connect(&client, "alice")?;

    assert!(
        !fixture
            .grants
            .revoke_token(issued.refresh_token(), other.id())?
    );
    assert!(
        fixture
            .grants
            .revoke_token(issued.refresh_token(), client.id())?
    );
    assert!(matches!(
        refresh(&fixture, issued.refresh_token(), (client.id(), None)),
        Err(GrantError::Revoked)
    ));
    assert!(!fixture.grants.revoke(&"0".repeat(64))?, "unknown grant");
    Ok(())
}

/// todo 30: `mcp_oauth_grants.json` keeps the refresh token only as its SHA-256 and the
/// password only as a derived fingerprint hash.
#[test]
fn grants_store_hashes_only() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/cb")?;
    let issued = fixture.connect(&client, "alice")?;
    let token = issued.refresh_token().expose_secret();

    let text = fs::read_to_string(fixture.state.dir().join("mcp_oauth_grants.json"))?;
    let hash = Sha256::digest(token.as_bytes());
    let hex = hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .concat();
    assert!(!text.contains(token), "no refresh token");
    assert!(text.contains(&hex), "its SHA-256 instead");
    assert_eq!(token.len(), 43, "256 bits in base64url");
    let stored: serde_json::Value = serde_json::from_str(&text)?;
    let grant = stored.pointer("/grants/0").ok_or("one grant")?;
    assert_eq!(grant.get("account"), Some(&serde_json::json!("alice")));
    assert_eq!(grant.get("resource"), Some(&serde_json::json!(RESOURCE)));
    assert_eq!(grant.get("revoked"), Some(&serde_json::json!(false)));
    let password = grant
        .get("password")
        .and_then(|value| value.as_str())
        .ok_or("password")?;
    assert_eq!(password.len(), 64);
    Ok(())
}

/// todo 30: a grant is issued only for a client registered in the same state.
#[test]
fn a_grant_needs_a_registered_client() -> TestResult {
    let elsewhere = Fixture::new()?;
    let stranger = elsewhere.client("http://127.0.0.1/cb")?;
    let fixture = Fixture::new()?;
    let outcome = fixture.connect(&stranger, "alice");
    let refused = outcome.err().ok_or("the grant is refused")?;
    assert!(matches!(
        refused.downcast_ref::<GrantError>(),
        Some(GrantError::UnknownClient)
    ));
    assert_eq!(fixture.grants.document()?, GrantsDocument::default());
    Ok(())
}
