//! Every request path of the engine reports to the client's observer.

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

extern crate alloc;

use alloc::sync::Arc;
use core::{
    error::Error,
    str::FromStr as _,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use kcc_rci::{
    RciPath, RouterUrl,
    auth::Credentials,
    engine::{ConfigKind, RciClient, RciClientOptions},
    observe::{LoginScheme, RciObserver, RequestOutcome},
    outbound::OutboundPolicy,
};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, model::Profile};
use secrecy::SecretString;
use serde_json::json;
use tokio_util::sync::CancellationToken;

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

/// Counts the requests and logins it is told about.
#[derive(Debug, Default)]
struct Recorder {
    requests: AtomicUsize,
    logins: AtomicUsize,
}

impl RciObserver for Recorder {
    fn request(&self, _outcome: RequestOutcome, _elapsed: Duration) {
        let _: usize = self.requests.fetch_add(1, Ordering::SeqCst);
    }

    fn authentication(&self, _scheme: Option<LoginScheme>, _success: bool) {
        let _: usize = self.logins.fetch_add(1, Ordering::SeqCst);
    }
}

impl Recorder {
    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    fn logins(&self) -> usize {
        self.logins.load(Ordering::SeqCst)
    }
}

fn options(recorder: &Arc<Recorder>) -> RciClientOptions {
    let shared: Arc<Recorder> = Arc::clone(recorder);
    let observer: Arc<dyn RciObserver> = shared;
    RciClientOptions::default()
        .with_outbound(OutboundPolicy::default().with_loopback(true))
        .with_observer(observer)
}

fn credentials(password: &str) -> Credentials {
    Credentials::new(
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(password.to_owned()),
    )
}

/// A-12: a factory-setup client reports its login and its requests.
#[tokio::test]
async fn a_bootstrap_client_reports_its_login() -> TestResult {
    let (address, handle) = FakeRouter::builder(Profile::default())
        .user(DEFAULT_LOGIN, "", ["cli", "http"])
        .build()?
        .serve(([127, 0, 0, 1], 0).into())
        .await?;
    let recorder = Arc::new(Recorder::default());
    let url = RouterUrl::from_str(&format!("http://{address}"))?;
    let setup = RciClient::connect_bootstrap_with(url, credentials(""), options(&recorder)).await?;

    assert!(setup.is_bootstrap().await?);

    assert_eq!(recorder.logins(), 1);
    handle.shutdown().await?;
    Ok(())
}

/// A-12: a background operation's dedicated session reports its login and every request.
#[tokio::test]
async fn a_background_session_reports_its_login_and_requests() -> TestResult {
    let (address, handle) = FakeRouter::builder(Profile::default())
        .build()?
        .serve(([127, 0, 0, 1], 0).into())
        .await?;
    let recorder = Arc::new(Recorder::default());
    let url = RouterUrl::from_str(&format!("http://{address}"))?;
    let client =
        RciClient::connect_with(url, credentials(DEFAULT_PASSWORD), options(&recorder)).await?;
    let ping = RciPath::from_segments(["tools", "ping"])?;

    let process = client
        .start(ping, &json!({"host":"192.0.2.1"}))
        .await?
        .with_poll_interval(Duration::from_millis(1));
    drop(process.poll(&CancellationToken::new()).await?);

    assert_eq!(recorder.logins(), 1, "the dedicated session signed in once");
    assert!(recorder.requests() >= 2, "the start and at least one poll");
    handle.shutdown().await?;
    Ok(())
}

/// A-12: batches and configuration downloads are counted like every other request.
#[tokio::test]
async fn batches_and_downloads_report_one_request_each() -> TestResult {
    let (address, handle) = FakeRouter::builder(Profile::default())
        .build()?
        .serve(([127, 0, 0, 1], 0).into())
        .await?;
    let recorder = Arc::new(Recorder::default());
    let url = RouterUrl::from_str(&format!("http://{address}"))?;
    let client =
        RciClient::connect_with(url, credentials(DEFAULT_PASSWORD), options(&recorder)).await?;

    drop(client.batch(vec![json!({"show":{"version":{}}})]).await?);
    drop(client.download_config(ConfigKind::Running).await?);

    assert_eq!(recorder.requests(), 2);
    handle.shutdown().await?;
    Ok(())
}
