//! End-to-end ndw2 authentication and session behavior.

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
#![expect(
    clippy::unwrap_used,
    reason = "an unexpected success must fail the test"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{
    error::Error,
    net::{Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use kcc_rci::{
    AuthError, RciError, RouterUrl,
    auth::{Credentials, Scheme, WwwAuthenticate, ndw2_response},
    session::{HttpTimeouts, Manager},
};
use kcc_testkit::{
    FakeRouter,
    model::Profile,
    time::{Clock, MockClock},
};
use proptest::prelude::*;
use reqwest::StatusCode;
use secrecy::SecretString;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, copy_bidirectional},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

/// Fallible integration-test result.
type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// Credentials for the fake router's default account.
fn credentials(password: &str) -> Credentials {
    Credentials::new("admin".to_owned(), SecretString::from(password.to_owned()))
}

/// Builds a manager pointed at one socket address.
fn manager(address: SocketAddr, password: &str) -> TestResult<Manager> {
    let router = format!("http://{address}").parse::<RouterUrl>()?;
    Ok(Manager::with_defaults(router, credentials(password))?)
}

/// Builds a manager that opens one connection per request for proxy request counting.
fn unpooled_manager(address: SocketAddr, password: &str) -> TestResult<Manager> {
    let router = format!("http://{address}").parse::<RouterUrl>()?;
    Ok(Manager::with_client_builder(
        router,
        credentials(password),
        HttpTimeouts::default(),
        reqwest::Client::builder().pool_max_idle_per_host(0),
    )?)
}

/// Known-answer vector from the reference ndw2 implementation.
#[test]
fn known_answer_vector() {
    let actual = ndw2_response(
        &credentials("secret"),
        "Keenetic Ultra",
        "0123456789abcdef0123456789abcdef",
    );
    assert_eq!(
        actual.as_str(),
        "9071bc0aeee8b97dfe926020c8aaeb35951c0f67998f1027eea5465643bc3632"
    );
}

/// Passwords never appear in credential debug output.
#[test]
fn credentials_debug_is_redacted() {
    let password = "unique-password-not-for-output";
    let debug = format!("{:?}", credentials(password));
    assert!(!debug.contains(password));
    assert!(debug.contains("[REDACTED]"));
}

/// The parser preserves known and unknown schemes from a combined header.
#[test]
fn multi_scheme_header_parses() -> TestResult {
    let header = concat!(
        "Basic realm=\"legacy\", ",
        "x-ndw4-interactive realm=\"Keenetic Ultra\", endpoint=\"/auth/ndw4\", ",
        "x-ndw2-interactive realm=\"Keenetic Ultra\", challenge=\"abc\", ",
        "session_id=\"sid\", session_cookie=\"COOKIE\""
    );
    let parsed = WwwAuthenticate::parse(header)?;
    assert_eq!(parsed.schemes().len(), 3);
    assert!(matches!(parsed.schemes().first(), Some(Scheme::Unknown(_))));
    assert!(matches!(parsed.schemes().get(1), Some(Scheme::Ndw4(_))));
    assert_eq!(
        parsed.ndw2().map(|value| value.session_cookie.as_str()),
        Some("COOKIE")
    );
    Ok(())
}

/// Correct credentials establish a session and access an authenticated endpoint.
#[tokio::test]
async fn login_success() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let manager = manager(address, "admin")?;
    manager.ensure_session().await?;
    let response = manager.get("/rci/show/version").await?;
    assert_eq!(response.status(), StatusCode::OK);
    handle.shutdown().await?;
    Ok(())
}

/// A wrong password maps to the typed rejection without exposing router details.
#[tokio::test]
async fn wrong_password_is_rejected() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let manager = manager(address, "wrong")?;
    let error = manager.ensure_session().await.unwrap_err();
    assert!(matches!(error, RciError::Auth(AuthError::Rejected)));
    handle.shutdown().await?;
    Ok(())
}

/// Router-side TTL expiry triggers re-authentication and one successful GET replay.
#[tokio::test]
async fn expired_session_reauthenticates_and_retries_get() -> TestResult {
    let clock = Arc::new(MockClock::new());
    let injected: Arc<dyn Clock> = Arc::<MockClock>::clone(&clock);
    let fake = FakeRouter::builder(Profile::default())
        .clock(injected)
        .build()?;
    let (address, handle) = fake.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let manager = manager(address, "admin")?;
    manager.ensure_session().await?;
    clock.advance(Duration::from_secs(301));
    let response = manager.get("/rci/show/version").await?;
    assert_eq!(response.status(), StatusCode::OK);
    handle.shutdown().await?;
    Ok(())
}

/// Fifty requests racing an expired cookie share exactly one login POST.
#[tokio::test]
async fn concurrent_expiry_has_one_login_post() -> TestResult {
    let clock = Arc::new(MockClock::new());
    let injected: Arc<dyn Clock> = Arc::<MockClock>::clone(&clock);
    let fake = FakeRouter::builder(Profile::default())
        .clock(injected)
        .build()?;
    let (router_address, router_handle) = fake.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let proxy = CountingProxy::spawn(router_address).await?;
    let manager = Arc::new(unpooled_manager(proxy.address, "admin")?);
    manager.ensure_session().await?;
    let baseline = proxy.login_posts.load(Ordering::SeqCst);
    clock.advance(Duration::from_secs(301));

    let mut tasks = Vec::with_capacity(50);
    for _index in 0_usize..50_usize {
        let shared = Arc::clone(&manager);
        tasks.push(tokio::spawn(async move {
            let response = shared.get("/rci/show/version").await?;
            Ok::<StatusCode, RciError>(response.status())
        }));
    }
    for task in tasks {
        assert_eq!(task.await??, StatusCode::OK);
    }
    assert_eq!(proxy.login_posts.load(Ordering::SeqCst) - baseline, 1);
    proxy.shutdown();
    router_handle.shutdown().await?;
    Ok(())
}

/// A TCP pass-through that counts request lines for `POST /auth`.
struct CountingProxy {
    /// Proxy address used by the session manager.
    address: SocketAddr,
    /// Number of observed login POSTs.
    login_posts: Arc<AtomicUsize>,
    /// Listener task.
    task: JoinHandle<()>,
}

impl CountingProxy {
    /// Starts a counting pass-through on an ephemeral loopback port.
    // cancel-safe: cancellation before return drops the listener and starts no detached task.
    async fn spawn(upstream: SocketAddr) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let login_posts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&login_posts);
        let task = tokio::spawn(async move {
            while let Ok((downstream, _peer)) = listener.accept().await {
                let per_connection = Arc::clone(&counter);
                drop(tokio::spawn(proxy_connection(
                    downstream,
                    upstream,
                    per_connection,
                )));
            }
        });
        Ok(Self {
            address,
            login_posts,
            task,
        })
    }

    /// Stops accepting new connections.
    fn shutdown(self) {
        self.task.abort();
    }
}

/// Forwards one connection after inspecting its first HTTP request line.
// cancel-safe: cancellation closes both sockets; HTTP clients retry only through their own policy.
async fn proxy_connection(
    mut downstream: TcpStream,
    upstream_address: SocketAddr,
    login_posts: Arc<AtomicUsize>,
) -> TestResult {
    let mut first_bytes = [0_u8; 8192];
    let count = downstream.read(&mut first_bytes).await?;
    let prefix = first_bytes
        .get(..count)
        .ok_or("invalid proxy read length")?;
    if prefix.starts_with(b"POST /auth ") {
        let _previous = login_posts.fetch_add(1, Ordering::SeqCst);
    }
    let mut upstream = TcpStream::connect(upstream_address).await?;
    upstream.write_all(prefix).await?;
    let _transferred = copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Arbitrary opaque schemes parse without panic and round-trip through canonical formatting.
    #[test]
    fn authenticate_parser_round_trips(
        scheme in "[A-Za-z][A-Za-z0-9-]{0,15}",
        key in "[a-z][a-z0-9_]{0,15}",
        value in "[A-Za-z0-9 /._:-]{0,32}",
    ) {
        let header = format!("{scheme} {key}=\"{value}\"");
        let first = WwwAuthenticate::parse(&header);
        prop_assert!(first.is_ok());
        let canonical = first.map(|parsed| parsed.to_string()).unwrap_or_default();
        let second = WwwAuthenticate::parse(&canonical);
        prop_assert!(second.is_ok());
        prop_assert_eq!(second.map(|parsed| parsed.to_string()).unwrap_or_default(), canonical);
    }

    /// Every arbitrary input is handled as either a parse result or a typed error, never a panic.
    #[test]
    fn authenticate_parser_never_panics(header in any::<String>()) {
        drop(WwwAuthenticate::parse(&header));
    }
}
