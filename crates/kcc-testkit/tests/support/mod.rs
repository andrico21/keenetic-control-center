//! Shared public-HTTP harness for fake-router integration scenarios.
#![expect(
    clippy::definition_in_module_root,
    reason = "integration-test support is shared by sibling test crates through this conventional module root"
)]

use core::{error::Error, net::SocketAddr, str::FromStr as _};

use kcc_rci::{OutboundPolicy, RciBody, RciClient, RciClientOptions, RouterUrl, auth::Credentials};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection, Handle, model::Profile,
};
use secrecy::SecretString;
use serde_json::Value;

/// Fallible integration-test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// Spawns one profile with faults and returns its handle and authenticated client.
///
/// # Errors
///
/// Returns fixture, bind, URL, policy, or connection errors.
pub(crate) async fn spawned(
    profile: Profile,
    faults: FaultInjection,
) -> TestResult<(Handle, RciClient)> {
    let fake = FakeRouter::builder(profile).faults(faults).build()?;
    let (address, handle) = fake.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let router = RouterUrl::from_str(&format!("http://{address}"))?;
    let credentials = Credentials::new(
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD.to_owned()),
    );
    let options =
        RciClientOptions::default().with_outbound(OutboundPolicy::default().with_loopback(true));
    let client = RciClient::connect_with(router, credentials, options).await?;
    Ok((handle, client))
}

/// Extracts a successful JSON response value.
///
/// # Errors
///
/// Returns an error when the response is textual or an unknown future variant.
pub(crate) fn json(body: RciBody) -> TestResult<Value> {
    match body {
        RciBody::Json(response) => Ok(response.value),
        RciBody::Text(_) => Err("expected JSON response".into()),
        _ => Err("unsupported response body".into()),
    }
}
