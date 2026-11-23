//! Pending authorization requests (single use, 10 minutes) and authorization codes
//! (single use, 60 seconds, bound to client, redirect URI, resource and PKCE S256).

use core::error::Error;

use kcc_app::mcp_auth::{
    clients::Client,
    pending::{
        AuthorizationRequest, CODE_LIFETIME_SECONDS, CodeRefusal, CodeTarget, PendingError,
        PkceChallenge, REQUEST_LIFETIME_SECONDS,
    },
};
use secrecy::{ExposeSecret as _, SecretString};

use super::{Fixture, LOOPBACK, RESOURCE, TestResult, challenge, random_text, verifier};

/// A code for `account` on `client`'s first redirect and the verifier it needs.
fn code(
    fixture: &Fixture,
    client: &Client,
    account: &str,
) -> Result<(SecretString, CodeTarget, SecretString), Box<dyn Error>> {
    let verifier = verifier()?;
    let (code, target) = code_for(fixture, (client, account), &verifier)?;
    Ok((code, target, verifier))
}

/// A code for `account` on `client`'s first redirect, challenged with `verifier`'s S256.
fn code_for(
    fixture: &Fixture,
    (client, account): (&Client, &str),
    verifier: &SecretString,
) -> Result<(SecretString, CodeTarget), Box<dyn Error>> {
    let redirect = client.redirect_uris().first().ok_or("a redirect URI")?;
    let target = CodeTarget::new(client.id(), redirect, RESOURCE);
    let request = AuthorizationRequest::new(client, target.clone(), challenge(verifier)?)?;
    Ok((fixture.pending.issue_code(request, account)?, target))
}

/// todo 30: only `S256` with a 43-character base64url challenge is accepted; `plain` and
/// every other method are refused.
#[test]
fn only_s256_challenges_are_accepted() -> TestResult {
    let good = random_text()?;
    drop(PkceChallenge::parse("S256", &good)?);
    for (method, value) in [
        ("plain", good.clone()),
        ("s256", good.clone()),
        ("", good.clone()),
        ("S256", good.chars().skip(1).collect()),
        ("S256", format!("{good}A")),
        (
            "S256",
            format!("{}+", good.chars().skip(1).collect::<String>()),
        ),
    ] {
        assert!(
            matches!(
                PkceChallenge::parse(method, &value),
                Err(PendingError::Challenge)
            ),
            "{method:?} {value:?} is refused"
        );
    }
    Ok(())
}

/// todo 30: a code is redeemed once with its own client, redirect URI, resource and S256
/// verifier; every refused attempt consumes it too.
#[test]
fn a_code_is_bound_and_single_use() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/cb")?;
    let other = fixture.client("http://127.0.0.1/other")?;
    let (good, target, verifier) = code(&fixture, &client, "alice")?;

    let authorized = fixture.pending.redeem(&good, &target, &verifier)?;
    assert_eq!(
        (
            authorized.account(),
            authorized.client_id(),
            authorized.resource()
        ),
        ("alice", client.id(), RESOURCE)
    );
    assert_eq!(
        fixture.pending.redeem(&good, &target, &verifier).err(),
        Some(CodeRefusal::Unknown),
        "a code is single use"
    );
    let cases = [
        (
            CodeTarget::new(other.id(), "http://127.0.0.1/cb", RESOURCE),
            None,
            CodeRefusal::Client,
        ),
        (
            CodeTarget::new(client.id(), "http://127.0.0.1:9/cb", RESOURCE),
            None,
            CodeRefusal::RedirectUri,
        ),
        (
            CodeTarget::new(
                client.id(),
                "http://127.0.0.1/cb",
                "https://kcc.example/other",
            ),
            None,
            CodeRefusal::Resource,
        ),
        (
            target.clone(),
            Some(SecretString::from(random_text()?)),
            CodeRefusal::Verifier,
        ),
        (
            target.clone(),
            Some(SecretString::from("short")),
            CodeRefusal::Verifier,
        ),
    ];
    for (presented, wrong_verifier, expected) in cases {
        let (fresh, _target, right) = code(&fixture, &client, "alice")?;
        let used = wrong_verifier.unwrap_or_else(|| right.clone());
        assert_eq!(
            fixture.pending.redeem(&fresh, &presented, &used).err(),
            Some(expected)
        );
        assert_eq!(
            fixture.pending.redeem(&fresh, &target, &right).err(),
            Some(CodeRefusal::Unknown),
            "the refused attempt consumed the code ({expected:?})"
        );
    }
    Ok(())
}

/// todo 30: the challenge itself is no verifier (`plain`), and a verifier outside RFC 7636
/// 4.1 (43 to 128 unreserved characters) is refused even when its S256 is the challenge.
#[test]
fn only_a_well_formed_s256_verifier_redeems() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/cb")?;
    let (fresh, target, right) = code(&fixture, &client, "alice")?;
    let plain = SecretString::from(challenge(&right)?.as_str().to_owned());
    assert_eq!(
        fixture.pending.redeem(&fresh, &target, &plain).err(),
        Some(CodeRefusal::Verifier),
        "plain"
    );
    let shaped = random_text()?;
    let long = format!("{shaped}{shaped}{shaped}");
    for bad in [
        shaped.chars().skip(1).collect::<String>(),
        long.chars().take(129).collect(),
        format!("{}+", shaped.chars().skip(1).collect::<String>()),
    ] {
        let verifier = SecretString::from(bad);
        let (code, bad_target) = code_for(&fixture, (&client, "alice"), &verifier)?;
        assert_eq!(
            fixture.pending.redeem(&code, &bad_target, &verifier).err(),
            Some(CodeRefusal::Verifier),
            "{} characters",
            verifier.expose_secret().len()
        );
    }
    let longest = SecretString::from(long.chars().take(128).collect::<String>());
    let (code, long_target) = code_for(&fixture, (&client, "alice"), &longest)?;
    drop(fixture.pending.redeem(&code, &long_target, &longest)?);
    Ok(())
}

/// todo 30: a code for another client is refused for this one.
#[test]
fn a_code_of_another_client_is_refused() -> TestResult {
    let fixture = Fixture::new()?;
    let mine = fixture.client("http://127.0.0.1/cb")?;
    let theirs = fixture.client("http://127.0.0.1/cb")?;
    let (code, _their_target, verifier) = code(&fixture, &theirs, "bob")?;
    let my_target = CodeTarget::new(mine.id(), "http://127.0.0.1/cb", RESOURCE);
    assert_eq!(
        fixture.pending.redeem(&code, &my_target, &verifier).err(),
        Some(CodeRefusal::Client)
    );
    Ok(())
}

/// todo 30: a code is redeemable for 60 seconds from its issue, on the injected clock.
#[test]
fn a_code_expires_after_sixty_seconds() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/cb")?;
    assert_eq!(CODE_LIFETIME_SECONDS, 60);

    let (fresh, target, verifier) = code(&fixture, &client, "alice")?;
    fixture.clock.advance(59);
    assert!(
        fixture.pending.redeem(&fresh, &target, &verifier).is_ok(),
        "59 s"
    );

    let (late, late_target, late_verifier) = code(&fixture, &client, "alice")?;
    fixture.clock.advance(60);
    assert_eq!(
        fixture
            .pending
            .redeem(&late, &late_target, &late_verifier)
            .err(),
        Some(CodeRefusal::Expired),
        "60 s"
    );
    Ok(())
}

/// todo 30: a pending request is found by its 256-bit id for 10 minutes and taken once.
#[test]
fn a_pending_request_lives_ten_minutes_and_is_taken_once() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/cb")?;
    let target = CodeTarget::new(client.id(), "http://127.0.0.1:4000/cb", RESOURCE);
    let request = AuthorizationRequest::new(&client, target, challenge(&verifier()?)?)?
        .with_state(Some("opaque-state"))?;
    assert_eq!(REQUEST_LIFETIME_SECONDS, 600);

    let id = fixture.pending.begin(request.clone(), LOOPBACK)?;
    let other = fixture.pending.begin(request.clone(), LOOPBACK)?;
    assert_eq!(id.expose_secret().len(), 43, "256 bits in base64url");
    assert_ne!(id.expose_secret(), other.expose_secret());
    fixture.clock.advance(599);
    let seen = fixture
        .pending
        .peek(id.expose_secret())
        .ok_or("live at 599 s")?;
    assert_eq!(seen.redirect_uri(), "http://127.0.0.1:4000/cb");
    assert_eq!(seen.state(), Some("opaque-state"));
    assert!(fixture.pending.take(id.expose_secret()).is_some());
    assert!(
        fixture.pending.take(id.expose_secret()).is_none(),
        "single use"
    );
    assert!(fixture.pending.peek(id.expose_secret()).is_none());
    fixture.clock.advance(1);
    assert!(
        fixture.pending.take(other.expose_secret()).is_none(),
        "gone at 600 s"
    );

    assert!(matches!(
        request.clone().with_state(Some(&"s".repeat(513))),
        Err(PendingError::State)
    ));
    assert!(matches!(
        request.with_state(Some("a\nb")),
        Err(PendingError::State)
    ));
    Ok(())
}
