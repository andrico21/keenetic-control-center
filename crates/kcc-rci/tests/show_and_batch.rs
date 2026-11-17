//! The engine's show fallback, batch replies and status items.

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

use core::{error::Error, net::SocketAddr, str::FromStr as _};

use kcc_rci::{
    RciError, RciPath, RciResponse, RouterUrl,
    auth::Credentials,
    engine::{RciBody, RciClient, RciClientOptions},
    outbound::OutboundPolicy,
};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection, Handle, model::Profile,
};
use secrecy::SecretString;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

async fn serve(
    faults: FaultInjection,
) -> Result<(SocketAddr, Handle), Box<dyn Error + Send + Sync>> {
    Ok(FakeRouter::builder(Profile::default())
        .faults(faults)
        .show_fixture(
            "probe",
            json!({"alpha":{"answer":"first"},"beta":{"answer":"second"}}),
        )
        .build()?
        .serve(([127, 0, 0, 1], 0).into())
        .await?)
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

fn probe() -> Result<RciPath, RciError> {
    RciPath::from_segments(["show", "probe"]).map_err(|_error| RciError::Validation)
}

fn answer(body: RciBody) -> Result<Value, RciError> {
    match body {
        RciBody::Json(response) => Ok(response.value),
        RciBody::Text(_) | _ => Err(RciError::Decode),
    }
}

fn methods(handle: &Handle) -> Vec<String> {
    handle
        .request_log()
        .iter()
        .filter(|record| record.path() == "/rci/show/probe")
        .map(|record| record.method().as_str().to_owned())
        .collect()
}

/// A-03: a show whose GET answers 404 is read by POST with its query, and a query-specific
/// 404 does not turn later reads of the path into POSTs.
#[tokio::test]
async fn a_show_fallback_posts_its_query_and_later_reads_try_get() -> TestResult {
    let (address, handle) =
        serve(FaultInjection::default().show_requires_post("show/probe")).await?;
    let client = client(address).await?;

    let first = answer(client.show(&probe()?, &[("name", "alpha")]).await?)?;
    let second = answer(client.show(&probe()?, &[("name", "beta")]).await?)?;

    assert_eq!(first, json!({"answer":"first"}));
    assert_eq!(second, json!({"answer":"second"}));
    assert_eq!(methods(&handle), ["GET", "POST", "GET", "POST"]);
    handle.shutdown().await?;
    Ok(())
}

/// A-03: a show whose GET answers 405 is read by POST with its query, and the path is
/// remembered so that later queries go straight to POST with their own query.
#[tokio::test]
async fn a_show_refused_by_method_posts_every_query() -> TestResult {
    let (address, handle) =
        serve(FaultInjection::default().show_get_not_allowed("show/probe")).await?;
    let client = client(address).await?;

    let first = answer(client.show(&probe()?, &[("name", "alpha")]).await?)?;
    let second = answer(client.show(&probe()?, &[("name", "beta")]).await?)?;

    assert_eq!(first, json!({"answer":"first"}));
    assert_eq!(second, json!({"answer":"second"}));
    assert_eq!(methods(&handle), ["GET", "POST", "POST"]);
    handle.shutdown().await?;
    Ok(())
}

/// A-04: a batch reply shorter than its chunk is a decode error, never a shorter success.
#[tokio::test]
async fn a_short_batch_reply_is_a_decode_error() -> TestResult {
    let (address, handle) = serve(FaultInjection::default().short_batch_reply()).await?;
    let client = client(address).await?;

    let result = client
        .batch(vec![
            json!({"show":{"version":{}}}),
            json!({"show":{"version":{}}}),
        ])
        .await
        .map_err(RciError::from);

    assert!(matches!(result, Err(RciError::Decode)), "{result:?}");
    handle.shutdown().await?;
    Ok(())
}

/// A-05: an error-level status item is an error whatever the types of its other members.
#[test]
fn an_error_status_with_odd_members_is_an_error() {
    for item in [
        json!({"status":"error","code":7_405_600_i32,"ident":"Core","message":"refused"}),
        json!({"status":"error","code":"7405600","ident":7_i32,"message":"refused"}),
        json!({"status":"error","code":"7405600","ident":"Core"}),
        json!({"status":"error"}),
    ] {
        let result = RciResponse::from_value(json!({"system":{"status":[item]}}));
        assert!(
            matches!(
                result,
                Err(RciError::Rci {
                    pointer: _,
                    code: _,
                    ident: _,
                    message: _
                })
            ),
            "{item} must be reported as an error"
        );
    }
}

/// A-05: a status item whose level this version does not know is treated as an error.
#[test]
fn an_unknown_status_level_is_an_error() {
    for level in [json!("fatal"), json!("ERROR"), json!(2_i32), json!(null)] {
        let item = json!({"status":level,"code":"1","ident":"Core","message":"refused"});
        let result = RciResponse::from_value(json!({"status":[item]}));
        assert!(
            matches!(
                result,
                Err(RciError::Rci {
                    pointer: _,
                    code: _,
                    ident: _,
                    message: _
                })
            ),
            "{item} must be reported as an error"
        );
    }
}
