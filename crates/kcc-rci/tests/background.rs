//! A background operation's dedicated session ends with its handle.

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

use core::{error::Error, net::SocketAddr, str::FromStr as _, time::Duration};

use kcc_rci::{
    RciError, RciPath, RouterUrl,
    auth::Credentials,
    engine::{RciClient, RciClientOptions},
    outbound::OutboundPolicy,
};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle, model::Profile};
use secrecy::SecretString;
use serde_json::json;
use tokio::time::{error::Elapsed, timeout};
use tokio_util::sync::CancellationToken;

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

/// Bound on waiting for the router to see a logout.
const SEEN: Duration = Duration::from_secs(10);

async fn start_router() -> Result<(SocketAddr, Handle, FakeRouter), Box<dyn Error + Send + Sync>> {
    let fake = FakeRouter::builder(Profile::default()).build()?;
    let (address, handle) = fake.clone().serve(([127, 0, 0, 1], 0).into()).await?;
    Ok((address, handle, fake))
}

async fn client(address: SocketAddr) -> Result<RciClient, RciError> {
    let router =
        RouterUrl::from_str(&format!("http://{address}")).map_err(|_error| RciError::Validation)?;
    let credentials = Credentials::new(
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD.to_owned()),
    );
    let options =
        RciClientOptions::default().with_outbound(OutboundPolicy::default().with_loopback(true));
    RciClient::connect_with(router, credentials, options).await
}

fn ping() -> Result<RciPath, RciError> {
    RciPath::from_segments(["tools", "ping"]).map_err(|_error| RciError::Validation)
}

async fn signed_out(handle: &Handle, count: usize) -> Result<(), Elapsed> {
    timeout(SEEN, handle.wait_for_requests("DELETE", "/auth", count)).await
}

/// A-07: finishing a background operation signs its dedicated session out.
#[tokio::test]
async fn a_finished_operation_logs_its_session_out() -> TestResult {
    let (address, handle, _fake) = start_router().await?;
    let client = client(address).await?;
    let process = client
        .start(ping()?, &json!({"host":"192.0.2.1"}))
        .await?
        .with_poll_interval(Duration::from_millis(1));
    drop(process.poll(&CancellationToken::new()).await?);

    signed_out(&handle, 1).await?;
    handle.shutdown().await?;
    Ok(())
}

/// A-07: dropping a handle that never finished signs its dedicated session out.
#[tokio::test]
async fn a_dropped_handle_logs_its_session_out() -> TestResult {
    let (address, handle, _fake) = start_router().await?;
    let client = client(address).await?;
    let process = client.start(ping()?, &json!({"host":"192.0.2.1"})).await?;
    drop(process);

    signed_out(&handle, 1).await?;
    handle.shutdown().await?;
    Ok(())
}

/// A-07: a cancelled operation reports cancellation, not failure or timeout, and the
/// router process is still stopped.
#[tokio::test]
async fn a_cancelled_operation_is_not_a_timeout() -> TestResult {
    let (address, handle, fake) = start_router().await?;
    let client = client(address).await?;
    let process = client
        .start(ping()?, &json!({"host":"192.0.2.2"}))
        .await?
        .with_poll_interval(Duration::from_secs(60));
    let token = CancellationToken::new();
    token.cancel();

    assert!(matches!(
        process.poll(&token).await,
        Err(RciError::Cancelled)
    ));
    assert_eq!(fake.stopped_processes(), 1);
    handle.shutdown().await?;
    Ok(())
}

/// The main client's logout ends its session on the router.
#[tokio::test]
async fn the_client_logout_ends_the_router_session() -> TestResult {
    let (address, handle, _fake) = start_router().await?;
    let client = client(address).await?;
    drop(
        client
            .get(&RciPath::from_segments(["show", "system"])?, &())
            .await?,
    );
    client.logout().await;

    signed_out(&handle, 1).await?;
    handle.shutdown().await?;
    Ok(())
}
