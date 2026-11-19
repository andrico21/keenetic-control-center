//! Log destination transport contracts.

use core::time::Duration;
use std::io::Read as _;

use flate2::read::GzDecoder;
use kcc_app::settings::Config;
use kcc_telemetry::logs::{elastic_sink::ElasticsearchClient, sink::LokiClient};
use kcc_testkit::{
    fake_elasticsearch::{FakeElasticsearch, Fault as ElasticsearchFault},
    fake_loki::FakeLoki,
};
use tempfile::TempDir;

use super::{TestResult, record};

#[tokio::test]
async fn loki_sink_applies_tenant_basic_auth_and_gzip_without_debug_secret() -> TestResult {
    let fake = FakeLoki::spawn().await?;
    let directory = TempDir::new()?;
    let password =
        kcc_testkit::write_secret_file(directory.path(), "sink-password", "highly-secret\n")?;
    let url = fake.url();
    let config = Config::from_toml_str(&format!(
        "[logs]\nenabled = true\n\n[[logs.sinks]]\nkind = \"loki\"\nurl = \"{url}\"\ntenant = \"tenant-a\"\nbasic_auth_user = \"writer\"\npassword_file = {password:?}\ncompress = true\n"
    ))?;
    config.validate()?;
    let sink = LokiClient::load(config.logs.sinks.first().ok_or("sink")?).await?;
    assert!(!format!("{sink:?}").contains("highly-secret"));
    let timestamp = super::at(2026, 11, 6, 12, 0, 1)?;

    sink.send(&[record(9, timestamp, "delivered")]).await?;

    let requests = fake.requests();
    let request = requests.first().ok_or("request")?;
    assert_eq!(
        request
            .headers()
            .get("x-scope-orgid")
            .and_then(|value| value.to_str().ok()),
        Some("tenant-a")
    );
    assert_eq!(
        request
            .headers()
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Basic d3JpdGVyOmhpZ2hseS1zZWNyZXQ=")
    );
    assert_eq!(
        request
            .headers()
            .get("content-encoding")
            .and_then(|value| value.to_str().ok()),
        Some("gzip")
    );
    let mut decoded = String::new();
    let _: usize = GzDecoder::new(request.body().as_ref()).read_to_string(&mut decoded)?;
    let payload: serde_json::Value = serde_json::from_str(&decoded)?;
    let line = payload
        .get("streams")
        .and_then(serde_json::Value::as_array)
        .and_then(|streams| streams.first())
        .and_then(|stream| stream.get("values"))
        .and_then(serde_json::Value::as_array)
        .and_then(|values| values.first())
        .and_then(serde_json::Value::as_array)
        .and_then(|value| value.get(1))
        .and_then(serde_json::Value::as_str);
    assert_eq!(line, Some("delivered"));
    fake.shutdown().await?;
    Ok(())
}

/// A bearer token file other users can read is refused before any delivery.
#[cfg(unix)]
#[tokio::test]
async fn loki_sink_refuses_a_bearer_token_file_others_can_read() -> TestResult {
    use std::{fs, os::unix::fs::PermissionsExt as _};

    use kcc_telemetry::logs::sink::DeliveryError;

    let fake = FakeLoki::spawn().await?;
    let directory = TempDir::new()?;
    let token = kcc_testkit::write_secret_file(
        directory.path(),
        "sink-token",
        &format!("{}\n", ["sink", "token"].join("-")),
    )?;
    fs::set_permissions(&token, fs::Permissions::from_mode(0o644))?;
    let url = fake.url();
    let config = Config::from_toml_str(&format!(
        "[logs]\nenabled = true\n\n[[logs.sinks]]\nkind = \"loki\"\nurl = \"{url}\"\nbearer_token_file = {token:?}\n"
    ))?;
    config.validate()?;

    let refused = LokiClient::load(config.logs.sinks.first().ok_or("sink")?)
        .await
        .err()
        .ok_or("0644 token accepted")?;

    assert!(
        matches!(&refused, DeliveryError::SecretPermissions { path } if *path == token),
        "{refused:?}"
    );
    assert!(fake.requests().is_empty(), "the sink was contacted");
    fake.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn elasticsearch_sink_uses_api_key_and_classifies_item_failures() -> TestResult {
    let fake =
        FakeElasticsearch::spawn_with_faults(vec![ElasticsearchFault::MapperParsing { item: 1 }])
            .await?;
    let directory = TempDir::new()?;
    let key = kcc_testkit::write_secret_file(directory.path(), "search-key", "encoded-api-key\n")?;
    let config = Config::from_toml_str(&format!(
        "[[logs.sinks]]\nkind = \"elasticsearch\"\nurl = \"{}\"\napi_key_file = {key:?}\n",
        fake.url()
    ))?;
    config.validate()?;
    let sink = ElasticsearchClient::load(config.logs.sinks.first().ok_or("sink")?).await?;
    assert!(!format!("{sink:?}").contains("encoded-api-key"));
    let timestamp = super::at(2026, 11, 6, 12, 0, 1)?;
    let records = [
        record(10, timestamp, "accepted"),
        record(11, timestamp, "rejected"),
    ];

    let outcome = sink.send(&records).await?;

    assert_eq!(outcome.accepted, 1);
    assert_eq!(outcome.retriable, Vec::<usize>::new());
    assert_eq!(outcome.dropped, [1]);
    let requests = fake.requests();
    let request = requests.first().ok_or("request")?;
    assert_eq!(
        request
            .headers()
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("ApiKey encoded-api-key")
    );
    assert_eq!(
        request
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/x-ndjson")
    );
    assert_eq!(
        request
            .body()
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count(),
        4
    );
    fake.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn elasticsearch_sink_marks_429_and_500_retriable() -> TestResult {
    let fake = FakeElasticsearch::spawn_with_faults(vec![
        ElasticsearchFault::TooManyRequests(Duration::from_secs(2)),
        ElasticsearchFault::InternalServerError,
    ])
    .await?;
    let config = Config::from_toml_str(&format!(
        "[[logs.sinks]]\nkind = \"elasticsearch\"\nurl = \"{}\"\n",
        fake.url()
    ))?;
    config.validate()?;
    let sink = ElasticsearchClient::load(config.logs.sinks.first().ok_or("sink")?).await?;
    let timestamp = super::at(2026, 11, 6, 12, 0, 1)?;
    let records = [record(12, timestamp, "retry")];

    let Err(rate_limited) = sink.send(&records).await else {
        return Err("expected 429 failure".into());
    };
    let Err(server_error) = sink.send(&records).await else {
        return Err("expected 500 failure".into());
    };

    assert!(rate_limited.is_retriable());
    assert!(server_error.is_retriable());
    fake.shutdown().await?;
    Ok(())
}
