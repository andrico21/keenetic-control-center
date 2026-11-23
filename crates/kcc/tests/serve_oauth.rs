//! `kcc serve` as its own OAuth 2.1 authorization server ("sign in with kcc"): discovery,
//! registration, the browser's sign-in and consent, PKCE-bound codes, refresh rotation,
//! and the kit validating kcc's tokens through the internal loopback JWKS listener.
//!
//! On Linux every child runs with a 1 MiB main-thread stack (`ulimit -s 1024`), the size
//! Windows gives the main thread.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process"
)]

#[path = "serve_oauth/authority.rs"]
mod authority;
#[path = "serve_oauth/browser.rs"]
mod browser;
#[path = "serve_oauth/deletions.rs"]
mod deletions;
#[path = "serve_oauth/fixture.rs"]
mod fixture;
#[path = "serve_oauth/flow.rs"]
mod flow;
#[path = "serve_oauth/listener.rs"]
mod listener;
#[path = "support/master_key.rs"]
mod master_key;
#[path = "serve_oauth/mcp.rs"]
mod mcp;
#[path = "serve_oauth/negatives.rs"]
mod negatives;
#[path = "serve_oauth/pages.rs"]
mod pages;
#[path = "serve_oauth/registration.rs"]
mod registration;
#[path = "support/serve_port.rs"]
mod serve_port;
#[path = "support/spawning.rs"]
mod spawning;
#[path = "serve_oauth/tokens.rs"]
mod tokens;

use fixture::{Fixture, Options, TestResult};
use flow::{REDIRECT, begin, client, location, param, query};
use mcp::Session;
use reqwest::{
    StatusCode,
    header::{self, HeaderValue},
};
use serde_json::Value;
use tokens::{error_of, redeem, refresh, tokens_of};

/// Asserts the discovery chain: protected-resource metadata names kcc's issuer as the
/// authorization server, whose metadata lists its endpoints and S256.
async fn discovered(fixture: &Fixture, server: &fixture::Server) -> TestResult {
    let http = fixture.http();
    let resource: Value = http
        .get(format!(
            "{}/.well-known/oauth-protected-resource/mcp",
            server.base()
        ))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(
        resource
            .pointer("/authorization_servers/0")
            .and_then(Value::as_str),
        Some(server.issuer().as_str()),
        "{resource}"
    );
    let metadata: Value = http
        .get(format!(
            "{}/.well-known/oauth-authorization-server",
            server.base()
        ))
        .send()
        .await?
        .json()
        .await?;
    let issuer = server.issuer();
    for (field, value) in [
        ("/issuer", issuer.clone()),
        (
            "/authorization_endpoint",
            format!("{issuer}/oauth/authorize"),
        ),
        ("/token_endpoint", format!("{issuer}/oauth/token")),
        ("/registration_endpoint", format!("{issuer}/oauth/register")),
        ("/revocation_endpoint", format!("{issuer}/oauth/revoke")),
        ("/jwks_uri", format!("{issuer}/oauth/jwks")),
        ("/code_challenge_methods_supported/0", "S256".to_owned()),
    ] {
        assert_eq!(
            metadata.pointer(field).and_then(Value::as_str),
            Some(value.as_str()),
            "{field}: {metadata}"
        );
    }
    Ok(())
}

/// Todo 31: the whole flow as a native MCP client runs it, for the viewer `vera`.
///
/// Protected-resource metadata names kcc as the authorization server; its metadata lists
/// the endpoints; registration, the authorization request without a session, the login
/// with the resume id, the approval with the CSRF header and its `HX-Redirect` carrying
/// `code`, `state` and `iss`; the token with PKCE (not stored, not cached); `tools/list`
/// filtered by the viewer role; the refresh rotates, and the rotated token used again
/// revokes the family.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oauth_full_flow() -> TestResult {
    let fixture = Fixture::new()?;
    let server = fixture.serve(Options::KCC)?;
    discovered(&fixture, &server).await?;
    let issuer = server.issuer();
    let client = client(&fixture, &server).await?;
    let consent = begin(&fixture, &server, &client).await?;
    let browser =
        browser::Browser::resume(&fixture, &server, ("vera", fixture::PASSWORD), &consent.id)
            .await?;
    let approved = browser.decide(&fixture, &consent.id, "approve").await?;
    let target = browser::hx_redirect(&approved).ok_or("no HX-Redirect")?;
    assert!(target.starts_with(REDIRECT), "{target}");
    let pairs = query(&target)?;
    assert_eq!(param(&pairs, "state"), Some(consent.state.as_str()));
    assert_eq!(param(&pairs, "iss"), Some(issuer.as_str()));
    let code = param(&pairs, "code").ok_or("no code")?.to_owned();
    let answer = redeem(&fixture, &server, &consent, &code).await?;
    assert_eq!(
        answer
            .headers()
            .get(header::CACHE_CONTROL)
            .map(HeaderValue::as_bytes),
        Some(b"no-store".as_slice())
    );
    assert_eq!(
        answer
            .headers()
            .get(header::PRAGMA)
            .map(HeaderValue::as_bytes),
        Some(b"no-cache".as_slice())
    );
    let tokens = tokens_of(answer, &client).await?;
    let session = Session::open(&fixture, &server, &tokens.access).await?;
    let tools = session.tools(&fixture).await?;
    assert!(
        tools.iter().any(|tool| tool == "kcc_routers_list"),
        "{tools:?}"
    );
    assert!(
        !tools.iter().any(|tool| tool == "kcc_job_cancel"),
        "a viewer lists no write tool: {tools:?}"
    );
    let rotated = tokens_of(
        refresh(&fixture, &server, (&client, &tokens.refresh)).await?,
        &client,
    )
    .await?;
    assert_ne!(rotated.refresh, tokens.refresh, "the refresh token rotates");
    let reused = refresh(&fixture, &server, (&client, &tokens.refresh)).await?;
    assert_eq!(
        error_of(reused).await?,
        (StatusCode::BAD_REQUEST, "invalid_grant".to_owned())
    );
    let family = refresh(&fixture, &server, (&client, &rotated.refresh)).await?;
    assert_eq!(
        error_of(family).await?.1,
        "invalid_grant",
        "a reused token revokes its family"
    );
    let audit = fixture.audit()?;
    assert!(
        audit
            .iter()
            .any(|entry| entry.action == "mcp.oauth_refresh_reuse"),
        "the reuse is audited"
    );
    Ok(())
}

/// Todo 31: the kit validates a kcc token through its normal OAuth path.
///
/// The keys come from kcc's internal loopback JWKS listener (no test bypass): an
/// administrator's token opens a session that lists the write tools; the log names the
/// listener, and the issuance is audited without the token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kcc_token_accepted_via_loopback_jwks_without_bypass() -> TestResult {
    let fixture = Fixture::new()?;
    let mut server = fixture.serve(Options::KCC)?;
    let line = server.wait_for("internal JWKS listener")?;
    assert!(line.contains("\"port\""), "{line}");
    let tokens = flow::connect(&fixture, &server, "alice").await?;
    let session = Session::open(&fixture, &server, &tokens.access).await?;
    let tools = session.tools(&fixture).await?;
    assert!(
        tools.iter().any(|tool| tool == "kcc_job_cancel"),
        "{tools:?}"
    );
    let issued = fixture.audit()?;
    let entry = issued
        .iter()
        .find(|entry| entry.action == "mcp.oauth_token_issued")
        .ok_or("token issuance is audited")?;
    assert_eq!(entry.actor.id, "oauth:alice");
    assert_eq!(
        entry.params_redacted.get("client").and_then(Value::as_str),
        Some(tokens.client.as_str())
    );
    let text = serde_json::to_string(&issued)?;
    assert!(!text.contains(&tokens.access) && !text.contains(&tokens.refresh));
    Ok(())
}

/// Todo 31: an approval answers the registered redirect URI only, and an unknown request
/// id is an error page, not a redirect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_denial_returns_access_denied_with_state_and_issuer() -> TestResult {
    let fixture = Fixture::new()?;
    let server = fixture.serve(Options::KCC)?;
    let client = client(&fixture, &server).await?;
    let consent = begin(&fixture, &server, &client).await?;
    let browser =
        browser::Browser::resume(&fixture, &server, ("alice", fixture::PASSWORD), &consent.id)
            .await?;
    let denied = browser.decide(&fixture, &consent.id, "deny").await?;
    let target = browser::hx_redirect(&denied).ok_or("no HX-Redirect")?;
    let pairs = query(&target)?;
    assert!(target.starts_with(REDIRECT), "{target}");
    assert_eq!(param(&pairs, "error"), Some("access_denied"));
    assert_eq!(param(&pairs, "state"), Some(consent.state.as_str()));
    assert_eq!(param(&pairs, "iss"), Some(server.issuer().as_str()));
    assert_eq!(param(&pairs, "code"), None);
    let again = browser.decide(&fixture, &consent.id, "approve").await?;
    assert_eq!(browser::hx_redirect(&again), None, "a request is used once");
    assert_eq!(location(&again), None);
    Ok(())
}
