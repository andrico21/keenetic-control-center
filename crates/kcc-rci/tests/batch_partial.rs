//! A batch that fails part-way returns the answers of the chunks already applied.

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

use core::{error::Error, str::FromStr as _};

use kcc_rci::{
    RciError, RouterUrl,
    auth::Credentials,
    engine::{RciClient, RciClientOptions},
    outbound::OutboundPolicy,
};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile};
use secrecy::SecretString;
use serde_json::json;

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

/// A-04: when a later chunk fails, the answers of the chunks the router already applied
/// come back with the error.
#[tokio::test]
async fn a_later_chunk_failure_returns_the_completed_chunks() -> TestResult {
    let (address, handle) = FakeRouter::builder(Profile::default())
        .faults(FaultInjection::default().fail_read_matching("second-chunk-marker", 1))
        .build()?
        .serve(([127, 0, 0, 1], 0).into())
        .await?;
    let router = RouterUrl::from_str(&format!("http://{address}"))?;
    let credentials = Credentials::new(
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD.to_owned()),
    );
    let options =
        RciClientOptions::default().with_outbound(OutboundPolicy::default().with_loopback(true));
    let client = RciClient::connect_with(router, credentials, options).await?;
    let filler = "x".repeat(600 * 1024);
    let items = vec![
        json!({"show":{"version":{}},"padding":filler}),
        json!({"show":{"version":{}},"padding":filler,"marker":"second-chunk-marker"}),
    ];

    let failure = client
        .batch(items)
        .await
        .err()
        .ok_or("the second chunk must fail")?;

    assert_eq!(failure.completed.len(), 1);
    assert!(failure.completed.iter().all(Result::is_ok));
    assert!(matches!(failure.error, RciError::Http { status: 500 }));
    assert_eq!(
        handle
            .request_log()
            .iter()
            .filter(|record| record.path() == "/rci/")
            .count(),
        2
    );
    handle.shutdown().await?;
    Ok(())
}
