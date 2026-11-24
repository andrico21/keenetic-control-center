//! `kcc serve` with MCP sign-in through an external OIDC identity provider in
//! resource-server mode.
//!
//! The provider's groups map to kcc roles, every token the provider did not issue for kcc
//! is refused, key rotation is followed, an unreachable JWKS fails closed, the
//! protected-resource metadata sends clients to the provider, identities are audited as
//! `oidc:<name>`, and a provider on a loopback address needs kcc.toml's allowlist.
//!
//! On Linux every child runs with a 1 MiB main-thread stack (`ulimit -s 1024`), the size
//! Windows gives the main thread. Waits use real time: the kit refreshes a JWKS at most
//! every 10 seconds, which the rotation and recovery tests wait out with a bounded poll.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process"
)]

#[path = "serve_oidc/fixture.rs"]
mod fixture;
#[path = "support/master_key.rs"]
mod master_key;
#[path = "serve_mtls/mcp.rs"]
mod mcp;
#[path = "support/serve_port.rs"]
mod serve_port;
#[path = "support/spawning.rs"]
mod spawning;

use core::{error::Error, time::Duration};

use fixture::{ADMINS, Fixture, LAB, client, initialize, now, url};
use kcc_app::audit::read_entries;
use kcc_testkit::fake_idp::{
    Mode,
    tokens::{Algorithm, Forgery},
};
use mcp::Session;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use tokio::time::{Instant, interval, timeout_at};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// How long a test waits out the kit's 10-second JWKS refresh cooldown.
const REFRESH_LIMIT: Duration = Duration::from_secs(40);

/// Polls `initialize` with `token` every half second until it answers `wanted`, for at
/// most [`REFRESH_LIMIT`]; the time is the behaviour under test (the kit's cooldown).
async fn until(client: &Client, port: u16, token: &str, wanted: StatusCode) -> TestResult {
    let deadline = Instant::now()
        .checked_add(REFRESH_LIMIT)
        .ok_or("deadline")?;
    let mut ticks = interval(Duration::from_millis(500));
    timeout_at(deadline, async {
        loop {
            let _tick = ticks.tick().await;
            if initialize(client, port, token).await? == wanted {
                return Ok::<(), Box<dyn Error + Send + Sync>>(());
            }
        }
    })
    .await
    .map_err(|_elapsed| format!("no {wanted} within {REFRESH_LIMIT:?}"))?
}

/// Todo 33: a token whose group is mapped to `operator` lists exactly the tools of an
/// `operator` API key, not those of a role with `Destructive`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mapped_group_gets_the_role_s_tools() -> TestResult {
    let fixture = Fixture::new().await?;
    let (port, server) = fixture.serve()?;
    let http = client()?;
    let token = fixture.idp.token(&fixture.claims("alice", &[ADMINS])?)?;

    let session = Session::open(&http, &url(port), Some(&token)).await?;
    let keyed = Session::open(&http, &url(port), Some(&fixture.operator_key)).await?;

    let tools = session.tool_names().await?;
    assert_eq!(tools, keyed.tool_names().await?);
    assert_ne!(tools, Vec::<String>::new());
    assert!(
        !tools.iter().any(|tool| tool == "kcc_storage_write"),
        "{tools:?}"
    );
    let lines = server.finish()?;
    assert!(
        !lines.iter().any(|line| line.contains(&token)),
        "the token was logged"
    );
    Ok(())
}

/// Todo 33: an identity is audited as `oidc:<preferred_username>`, escaped and cut to the
/// audit's 64 bytes, and the token never reaches the audit log or the server log.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_identity_is_audited_as_oidc_and_escaped() -> TestResult {
    let fixture = Fixture::new().await?;
    let (port, server) = fixture.serve()?;
    let http = client()?;
    let mut claims = fixture.claims("subject-1", &[LAB])?;
    claims.preferred_username = Some(format!("<script>\n{}", "x".repeat(80)));
    let token = fixture.idp.token(&claims)?;
    let session = Session::open(&http, &url(port), Some(&token)).await?;

    let refused = session
        .call_tool(
            "kcc_storage_write",
            json!({"host": "office", "op": "eject", "name": "usb1", "confirm": true}),
        )
        .await?;

    assert!(
        refused.to_string().contains("destructive_disabled"),
        "{refused}"
    );
    let full = format!("oidc:%3Cscript%3E%0A{}", "x".repeat(80));
    let expected = full.get(..64).ok_or("short")?;
    let entries = read_entries(fixture.state()?.dir())?;
    let actors: Vec<&str> = entries
        .iter()
        .filter(|entry| entry.action == "mcp.kcc_storage_write")
        .map(|entry| entry.actor.id.as_str())
        .collect();
    assert_eq!(actors, [expected]);
    assert!(!serde_json::to_string(&entries)?.contains(&token));
    let lines = server.finish()?;
    assert!(
        !lines.iter().any(|line| line.contains(&token)),
        "the token was logged"
    );
    Ok(())
}

/// Todo 33: tokens with the wrong audience or issuer, outside their validity, or without a
/// subject are refused; a valid one is admitted (same provider, same key).
///
/// The audience is checked strictly: kcc named only as the authorized party (`azp`) is
/// refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_claims_are_refused() -> TestResult {
    let fixture = Fixture::new().await?;
    let (port, _server) = fixture.serve()?;
    let http = client()?;
    let valid = fixture.claims("alice", &[ADMINS])?;
    let now = now()?;
    let mut cases = Vec::new();
    let mut audience = valid.clone();
    audience.aud = Some("another-service".to_owned());
    cases.push(("audience", audience));
    let mut authorized = valid.clone();
    authorized.azp = valid.aud.clone();
    authorized.aud = Some("another-service".to_owned());
    cases.push(("audience only as the authorized party", authorized));
    let mut issuer = valid.clone();
    issuer.iss = Some(format!("{}-other", fixture.issuer()));
    cases.push(("issuer", issuer));
    let mut expired = valid.clone();
    expired.exp = Some(now.saturating_sub(3600));
    cases.push(("expired", expired));
    let mut early = valid.clone();
    early.nbf = Some(now.saturating_add(3600));
    cases.push(("not yet valid", early));
    let mut anonymous = valid.clone();
    anonymous.sub = None;
    cases.push(("no subject", anonymous));

    let admitted = initialize(&http, port, &fixture.idp.token(&valid)?).await?;

    assert_eq!(admitted, StatusCode::OK);
    for (case, claims) in cases {
        let token = fixture.idp.token(&claims)?;
        assert_eq!(
            initialize(&http, port, &token).await?,
            StatusCode::UNAUTHORIZED,
            "{case}"
        );
    }
    Ok(())
}

/// Todo 33: forged tokens and unmapped groups are refused.
///
/// `HS256` keyed with the public key, `alg: none`, an `RS256` header, a foreign key under
/// the served key's id, an algorithm outside `allowed_algorithms` and an unmapped group
/// get 401; the protected-resource metadata names the provider as the authorization server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_tokens_and_unmapped_groups_are_refused() -> TestResult {
    let fixture = Fixture::new().await?;
    let (port, _server) = fixture.serve()?;
    let http = client()?;
    let claims = fixture.claims("alice", &[ADMINS])?;
    let mut tokens = Vec::new();
    for forgery in [
        Forgery::Hs256WithPublicKey,
        Forgery::AlgNone,
        Forgery::Rs256Header,
        Forgery::ForeignKeySameKid,
    ] {
        tokens.push((
            format!("{forgery:?}"),
            fixture.idp.forged(forgery, &claims)?,
        ));
    }
    tokens.push((
        "EdDSA not allowed".to_owned(),
        fixture.idp.token_with(Algorithm::EdDsa, &claims)?,
    ));
    let unmapped = fixture.claims("bob", &["staff"])?;
    tokens.push(("unmapped group".to_owned(), fixture.idp.token(&unmapped)?));

    assert_eq!(
        initialize(&http, port, &fixture.idp.token(&claims)?).await?,
        StatusCode::OK
    );
    for (case, token) in tokens {
        assert_eq!(
            initialize(&http, port, &token).await?,
            StatusCode::UNAUTHORIZED,
            "{case}"
        );
    }
    let metadata: Value = http
        .get(format!(
            "{}/.well-known/oauth-protected-resource/mcp",
            url(port)
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(
        metadata.get("authorization_servers"),
        Some(&json!([fixture.issuer()]))
    );
    Ok(())
}

/// Todo 33: after the provider rotates its keys, new tokens are admitted once the kit
/// refreshed the JWKS and tokens of the retired key are refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rotated_key_is_followed() -> TestResult {
    let fixture = Fixture::new().await?;
    let (port, _server) = fixture.serve()?;
    let http = client()?;
    let claims = fixture.claims("alice", &[ADMINS])?;
    let retired = fixture.idp.token(&claims)?;
    assert_eq!(initialize(&http, port, &retired).await?, StatusCode::OK);

    fixture.idp.rotate()?;
    let current = fixture.idp.token(&claims)?;

    until(&http, port, &current, StatusCode::OK).await?;
    assert_eq!(
        initialize(&http, port, &retired).await?,
        StatusCode::UNAUTHORIZED
    );
    assert!(fixture.idp.fetches() >= 2);
    Ok(())
}

/// Todo 33: while the JWKS is unreachable a valid token is refused (fail closed); once it
/// answers again the same token is admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_jwks_fails_closed() -> TestResult {
    let fixture = Fixture::new().await?;
    fixture.idp.set_mode(Mode::Refusing);
    let (port, _server) = fixture.serve()?;
    let http = client()?;
    let token = fixture.idp.token(&fixture.claims("alice", &[ADMINS])?)?;

    assert_eq!(
        initialize(&http, port, &token).await?,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(fixture.idp.fetches(), 0);
    fixture.idp.set_mode(Mode::Serving);
    until(&http, port, &token, StatusCode::OK).await?;
    Ok(())
}

/// Todo 33: a provider whose JWKS host resolves to a loopback address does not start
/// without kcc.toml's allowlist; the typed reason is logged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_loopback_provider_needs_the_kcc_toml_allowlist() -> TestResult {
    let fixture = Fixture::new().await?;

    let (status, lines) = fixture.serve_without_allowlist()?;

    assert!(!status.success(), "{status:?}");
    let reason = lines
        .iter()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|event| {
            event.pointer("/fields/message").and_then(Value::as_str)
                == Some("identity provider sign-in refused")
        })
        .and_then(|event| {
            event
                .pointer("/fields/reason")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .ok_or_else(|| format!("no refusal logged:\n{}", lines.join("\n")))?;
    assert!(
        reason.contains("resolves to a loopback address"),
        "{reason}"
    );
    assert_eq!(fixture.idp.fetches(), 0);
    Ok(())
}
