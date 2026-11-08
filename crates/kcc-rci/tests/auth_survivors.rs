//! Authentication guards first left unprotected by the mutation run: the ndw4 endpoint
//! guard and key cache, and the digest scheme-name and `qop` checks.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#![expect(
    clippy::tests_outside_test_module,
    reason = "this integration-test crate contains only tests"
)]

#[path = "support/auth_server.rs"]
mod auth_server;
#[path = "support/ndw4_rotating.rs"]
mod ndw4_rotating;

use core::{error::Error, net::SocketAddr};

use auth_server::{Recorder, Script, Seen};
use kcc_rci::{
    AuthError, RciError,
    auth::Credentials,
    auth_options::{Mode, Options},
    session::SessionManager,
};
use ndw4_rotating::Rotating;
use reqwest::{Method, StatusCode};
use secrecy::SecretString;

/// Fallible integration-test result.
type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

/// The dummy identity both scripted routers accept.
fn credentials() -> Credentials {
    Credentials::new("admin".to_owned(), SecretString::from("admin".to_owned()))
}

/// A password-session manager for one loopback router.
fn manager(address: SocketAddr) -> Result<SessionManager, Box<dyn Error + Send + Sync>> {
    Ok(SessionManager::with_defaults(
        format!("http://{address}").parse()?,
        credentials(),
    )?)
}

/// A digest-proxy manager for one loopback router.
fn digest_manager(address: SocketAddr) -> Result<SessionManager, Box<dyn Error + Send + Sync>> {
    let mut options = Options::default();
    options.mode = Mode::DigestProxy;
    Ok(SessionManager::with_options(
        format!("http://{address}").parse()?,
        Some(credentials()),
        options,
    )?)
}

/// Methods and paths only, for request-sequence assertions.
fn lines(requests: &[Seen]) -> Vec<(Method, String)> {
    requests
        .iter()
        .map(|(method, path, _authorization)| (method.clone(), path.clone()))
        .collect()
}

/// A1: an endpoint that leaves the origin path, escapes or carries a fragment is refused
/// before any phase is posted; a well-formed endpoint is posted to (the recorder sees it).
// NOT cancel-safe: owns a local router per table row.
#[tokio::test]
async fn ndw4_endpoint_guard_refuses_before_sending() -> TestResult {
    let probe = (Method::GET, "/auth".to_owned());
    for endpoint in ["//evil/x", "/a\\b", "/a#b"] {
        let router = Recorder::spawn(Script::Ndw4Endpoint(endpoint)).await?;

        let result = manager(router.address())?.ensure_session().await;

        assert!(
            matches!(result, Err(RciError::Auth(AuthError::Rejected))),
            "{endpoint} must be rejected"
        );
        assert_eq!(lines(&router.requests()), vec![probe.clone()], "{endpoint}");
    }
    let router = Recorder::spawn(Script::Ndw4Endpoint("/auth/elsewhere")).await?;
    let _refused = manager(router.address())?.ensure_session().await;
    assert_eq!(
        lines(&router.requests()),
        vec![probe, (Method::POST, "/auth/elsewhere".to_owned())]
    );
    Ok(())
}

/// A2: when the router changes its KDF parameters between logins, the second login
/// derives fresh keys and succeeds; reused keys would produce a proof the router refuses.
// NOT cancel-safe: owns a local router through both logins.
#[tokio::test]
async fn ndw4_key_cache_rederives_after_parameter_change() -> TestResult {
    let router = Rotating::spawn().await?;
    let manager = manager(router.address())?;

    manager.ensure_session().await?;
    assert!(
        manager.session().is_some(),
        "first login installs a session"
    );
    manager.logout().await;
    assert!(manager.session().is_none(), "logout clears the session");
    let second = manager.ensure_session().await;

    assert!(
        second.is_ok(),
        "login after the iteration change must succeed"
    );
    assert!(
        manager.session().is_some(),
        "second login installs a session"
    );
    Ok(())
}

/// A3/A4: the digest challenge must be named Digest and offer `qop=auth`.
// NOT cancel-safe: owns a local router per table row.
#[tokio::test]
async fn digest_requires_scheme_name_and_auth_qop() -> TestResult {
    let refused = [
        "Foo qop=\"auth\", realm=\"proxy\", nonce=\"abc\"",
        "Digest qop=\"auth-int\", realm=\"proxy\", nonce=\"abc\"",
    ];
    for challenge in refused {
        let router = Recorder::spawn(Script::Digest(challenge)).await?;

        let result = digest_manager(router.address())?
            .get("/rci/show/version")
            .await;

        assert!(
            matches!(result, Err(RciError::Auth(AuthError::Unsupported))),
            "{challenge} must be unsupported"
        );
        assert_eq!(
            router.requests().len(),
            1,
            "{challenge} must not be answered"
        );
    }
    let router = Recorder::spawn(Script::Digest(
        "Digest qop=\"auth,auth-int\", realm=\"proxy\", nonce=\"abc\"",
    ))
    .await?;

    let response = digest_manager(router.address())?
        .get("/rci/show/version")
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = router.requests();
    assert_eq!(requests.len(), 2, "one challenge, one signed replay");
    assert!(
        requests
            .last()
            .and_then(|(_method, _path, authorization)| authorization.as_deref())
            .is_some_and(|value| value.starts_with("Digest ") && value.contains(" qop=auth,")),
        "the replay is signed with qop=auth"
    );
    Ok(())
}
