//! Integration coverage for the authenticated RCI request engine.

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

use alloc::collections::BTreeMap;
use core::{
    error::Error,
    net::{IpAddr, SocketAddr},
    str::FromStr as _,
    time::Duration,
};

use kcc_rci::{
    ObjectName, RciError, RciPath, RouterUrl,
    auth::Credentials,
    engine::{ConfigKind, RciBody, RciClient, RciClientOptions, SecretBytes},
    outbound::{AllowedNetwork, OutboundPolicy, TlsMode},
    session::{HttpTimeouts, SessionManager},
};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, model::Profile};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

#[path = "support/tls_fixture.rs"]
mod tls_fixture;
use tls_fixture::TlsFixture;

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

fn credentials() -> Credentials {
    Credentials::new(
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD.to_owned()),
    )
}

fn path(segments: &[&str]) -> Result<RciPath, RciError> {
    RciPath::from_segments(segments).map_err(|_error| RciError::Validation)
}

async fn client(address: SocketAddr) -> Result<RciClient, RciError> {
    let router =
        RouterUrl::from_str(&format!("http://{address}")).map_err(|_error| RciError::Validation)?;
    let options =
        RciClientOptions::default().with_outbound(OutboundPolicy::default().with_loopback(true));
    RciClient::connect_with(router, credentials(), options).await
}

fn json_value(body: RciBody) -> Result<Value, RciError> {
    match body {
        RciBody::Json(response) => Ok(response.value),
        RciBody::Text(_) | _ => Err(RciError::Decode),
    }
}

#[tokio::test]
async fn verbs_show_parse_and_config_transfer_use_the_real_router_surface() -> TestResult {
    let fake = FakeRouter::builder(Profile::default()).build()?;
    let (address, handle) = fake.clone().serve(([127, 0, 0, 1], 0).into()).await?;
    let client = client(address).await?;
    let empty = BTreeMap::<String, String>::new();

    let version = json_value(client.get(&path(&["show", "version"])?, &empty).await?)?;
    assert!(version.get("title").is_some());
    let shown = json_value(client.show_rc(json!({"system":{}})).await?)?;
    assert!(shown.get("show").is_some());
    let startup_shown = json_value(client.show_sc(json!({"system":{}})).await?)?;
    assert!(startup_shown.get("show").is_some());
    let interface = "WifiMaster0/AccessPoint0".parse::<ObjectName>()?;
    drop(client.show_interface(&interface).await?);
    drop(client.parse("interface Bridge0 description Engine").await?);
    let deleted = client
        .delete(
            &path(&["ip", "hotspot", "host"])?,
            &[(&"mac", &"02:00:00:00:11:01")],
        )
        .await?;
    assert!(matches!(deleted, RciBody::Json(_)));
    let text = client.show(&path(&["show", "log"])?, &empty).await?;
    assert_eq!(text, RciBody::Text("router log text".to_owned()));
    let startup = client.download_config(ConfigKind::Startup).await?;
    assert!(startup.expose_secret().starts_with(b"! $$$ Model:"));
    let uploaded = SecretBytes::from(
        b"interface Bridge0\n description \"Engine upload\"\n ip address 192.0.2.1 255.255.255.0\n!\n".to_vec(),
    );
    drop(client.upload_startup_config(&uploaded).await?);

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn batch_preserves_ok_error_ok_and_splits_large_input_in_order() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let client = client(address).await?;
    let results = client
        .parse_batch([
            "interface Bridge0 description first",
            "interface Bridge0 nonsense-arg",
            "interface Bridge0 description third",
        ])
        .await?;
    assert!(results.first().is_some_and(Result::is_ok));
    assert!(results.get(1).is_some_and(Result::is_err));
    assert!(results.get(2).is_some_and(Result::is_ok));

    let payload = "x".repeat(700 * 1024);
    let large = (0_u8..3_u8)
        .map(|index| json!({"parse":format!("interface Bridge0 description {index}{payload}")}))
        .collect();
    let ordered = client.batch(large).await?;
    assert_eq!(ordered.len(), 3);
    assert!(ordered.iter().all(Result::is_ok));

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn background_poll_completes_and_cancellation_sends_delete() -> TestResult {
    let fake = FakeRouter::builder(Profile::default()).build()?;
    let (address, handle) = fake.clone().serve(([127, 0, 0, 1], 0).into()).await?;
    let client = client(address).await?;
    let process = client
        .start(path(&["tools", "ping"])?, &json!({"host":"192.0.2.1"}))
        .await?
        .with_poll_interval(Duration::from_millis(1));
    let completed = json_value(process.poll(&CancellationToken::new()).await?)?;
    assert_eq!(completed.pointer("/process/status"), Some(&json!("done")));

    let cancelled = client
        .start(path(&["tools", "ping"])?, &json!({"host":"192.0.2.2"}))
        .await?
        .with_poll_interval(Duration::from_secs(60));
    let token = CancellationToken::new();
    token.cancel();
    assert!(matches!(
        cancelled.poll(&token).await,
        Err(RciError::Timeout)
    ));
    assert_eq!(fake.stopped_processes(), 1);

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn outbound_policy_refuses_metadata_public_and_public_dns_but_allows_lan() -> TestResult {
    let options = RciClientOptions::default();
    for target in ["http://169.254.169.254", "http://8.8.8.8"] {
        let result = RciClient::connect_with(target.parse()?, credentials(), options.clone()).await;
        assert!(
            matches!(result, Err(RciError::Policy)),
            "target was admitted: {target}"
        );
    }

    let public_dns = OutboundPolicy::default().client_builder_for_resolved(
        &"http://router.example".parse()?,
        &TlsMode::Verify,
        HttpTimeouts::default(),
        &["8.8.8.8:80".parse()?],
    );
    assert!(matches!(public_dns, Err(RciError::Policy)));

    let policy = OutboundPolicy::default();
    let builder = policy
        .client_builder(
            &"http://192.168.1.1".parse()?,
            &TlsMode::Verify,
            HttpTimeouts::default(),
        )
        .await?;
    drop(builder);
    let network = AllowedNetwork::new(IpAddr::from([192, 168, 0, 0]), 16)?;
    assert!(network.contains(IpAddr::from([192, 168, 1, 1])));
    Ok(())
}

#[tokio::test]
async fn response_cap_rejects_an_oversized_text_body() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let options = RciClientOptions::default()
        .with_outbound(OutboundPolicy::default().with_loopback(true))
        .with_response_bytes(8);
    let client =
        RciClient::connect_with(format!("http://{address}").parse()?, credentials(), options)
            .await?;
    let result = client
        .show(&path(&["show", "log"])?, &BTreeMap::<String, String>::new())
        .await;
    assert!(matches!(result, Err(RciError::BodyTooLarge)));
    handle.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn pinned_tls_accepts_the_right_spki_and_rejects_the_wrong_one() -> TestResult {
    let fixture = TlsFixture::spawn().await?;
    let router =
        format!("https://router.test:{}", fixture.address().port()).parse::<RouterUrl>()?;
    let policy = OutboundPolicy::default().with_loopback(true);
    let timeouts = HttpTimeouts::default();
    let resolved = [fixture.address()];

    let right_builder = policy.client_builder_for_resolved(
        &router,
        &TlsMode::PinSha256(fixture.fingerprint()),
        timeouts,
        &resolved,
    )?;
    let right = SessionManager::with_client_builder(
        router.clone(),
        credentials(),
        timeouts,
        right_builder,
    )?;
    assert!(right.get("/auth").await?.status().is_success());

    let wrong_builder = policy.client_builder_for_resolved(
        &router,
        &TlsMode::PinSha256([0_u8; 32]),
        timeouts,
        &resolved,
    )?;
    let wrong =
        SessionManager::with_client_builder(router, credentials(), timeouts, wrong_builder)?;
    assert!(matches!(wrong.get("/auth").await, Err(RciError::Transport)));

    fixture.shutdown().await;
    Ok(())
}
