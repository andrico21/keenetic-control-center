//! Router log parser, deduplication, and collection contracts.
#![expect(
    clippy::std_instead_of_alloc,
    clippy::tests_outside_test_module,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test crate: assertions and fixtures define the contract"
)]

use core::{error::Error, net::SocketAddr, num::NonZeroUsize, time::Duration};
use std::{fs, sync::Arc};

use chrono::{Datelike as _, NaiveDate, NaiveDateTime};
use kcc_app::settings::{Config, SearchFlavor};
use kcc_rci::{OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials};
use kcc_telemetry::{
    logs::{
        dedupe::Window,
        format::{bulk, loki},
        parser::parse_records,
        queue::Pending,
        redact,
        runtime::Service as LogService,
        service::LogCollector,
        types::LogRecord,
    },
    metrics::instrumentation::SelfMetrics,
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, fake_loki::FakeLoki, model::Profile};
use prometheus::{Registry, TextEncoder};
use secrecy::SecretString;
use serde_json::json;
use tempfile::TempDir;
use tokio::time::{sleep, timeout};

#[path = "logs/bounds.rs"]
mod bounds;
#[path = "logs/collection.rs"]
mod collection;
#[path = "logs/pipeline.rs"]
mod pipeline;
#[path = "logs/retry.rs"]
mod retry;
#[path = "logs/transport.rs"]
mod transport;

/// Test result.
type TestResult = Result<(), Box<dyn Error>>;

/// Connects an RCI client to one fake router.
async fn client(address: SocketAddr) -> Result<Arc<RciClient>, Box<dyn Error>> {
    let router = format!("http://{address}").parse::<RouterUrl>()?;
    let credentials = Credentials::new("admin".to_owned(), SecretString::from(DEFAULT_PASSWORD));
    let options =
        RciClientOptions::default().with_outbound(OutboundPolicy::default().with_loopback(true));
    Ok(Arc::new(
        RciClient::connect_with(router, credentials, options).await?,
    ))
}

/// A naive wall-clock time.
fn at(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Result<NaiveDateTime, Box<dyn Error>> {
    NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|date| date.and_hms_opt(hour, minute, second))
        .ok_or_else(|| "date".into())
}

#[test]
fn parser_infers_previous_year_and_merges_continuations() -> TestResult {
    let now = at(2026, 1, 1, 0, 0, 30)?;
    let response = json!({
        "log": {
            "42": {
                "message": {
                    "level": "Warning",
                    "label": "W",
                    "message": "[Dec 31 23:59:59] ndm[77]: Core::Net: first line\n  second line"
                }
            }
        }
    });

    let parsed = parse_records("home", &response, now)?;

    let [(42, Some(record))] = parsed.entries.as_slice() else {
        return Err("expected one record".into());
    };
    assert_eq!(record.ts.year(), 2_025_i32);
    assert_eq!(record.process.as_deref(), Some("ndm"));
    assert_eq!(record.pid, Some(77));
    assert_eq!(record.component.as_deref(), Some("Core::Net"));
    assert_eq!(record.message, "first line\nsecond line");
    Ok(())
}

#[test]
fn dedupe_suppresses_replay_and_accepts_router_reset() {
    let mut window = Window::new(3);
    assert!(window.accept(100));
    assert!(window.accept(101));
    assert!(!window.accept(100));
    assert!(window.accept(1), "lower id after gap resets the window");
    assert!(!window.accept(1));
}

#[test]
fn mac_redaction_replaces_colon_and_hyphen_addresses_only() {
    let colon = ["aa", "bb", "cc", "dd", "ee", "ff"].join(":");
    let hyphen = ["01", "23", "45", "67", "89", "AB"].join("-");
    assert_eq!(
        redact::macs(&format!("clients {colon} and {hyphen}")),
        "clients [REDACTED-MAC] and [REDACTED-MAC]"
    );
    assert_eq!(redact::macs("id aa:bb:cc and cafe"), "id aa:bb:cc and cafe");
}

#[test]
fn loki_payload_groups_bounded_labels_and_sorts_values() -> TestResult {
    let later = at(2026, 11, 6, 12, 0, 2)?;
    let earlier = at(2026, 11, 6, 12, 0, 1)?;
    let records = [record(2, later, "second"), record(1, earlier, "first")];

    let payload: serde_json::Value = serde_json::from_slice(&loki(&records)?)?;

    let stream = payload
        .get("streams")
        .and_then(serde_json::Value::as_array)
        .and_then(|streams| streams.first())
        .ok_or("stream")?;
    assert_eq!(
        stream.get("stream"),
        Some(&json!({"job":"keenetic","router":"home","level":"info"}))
    );
    assert_eq!(
        stream.get("values"),
        Some(&json!([
            [earlier.and_utc().timestamp_nanos_opt().ok_or("timestamp")?.to_string(), "first", {"id":"1","process":"ndm","pid":"7"}],
            [later.and_utc().timestamp_nanos_opt().ok_or("timestamp")?.to_string(), "second", {"id":"2","process":"ndm","pid":"7"}]
        ]))
    );
    Ok(())
}

#[test]
fn bulk_payload_uses_create_ecs_and_flavor_defaults() -> TestResult {
    let timestamp = at(2026, 11, 6, 12, 0, 1)?;
    let records = [record(7, timestamp, "connected")];

    let elastic = bulk(&records, SearchFlavor::Elasticsearch, None)?;
    let open_search = bulk(&records, SearchFlavor::Opensearch, None)?;

    let elastic_lines = elastic.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    let open_search_lines = open_search.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(elastic_lines.first().ok_or("action")?)?,
        json!({"create":{"_index":"logs-keenetic.syslog-default"}})
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(elastic_lines.get(1).ok_or("document")?)?,
        json!({
            "@timestamp":"2026-11-06T12:00:01",
            "event.id":"7",
            "log.level":"info",
            "message":"connected",
            "observer.name":"home",
            "process.name":"ndm",
            "process.pid":7_u32
        })
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(open_search_lines.first().ok_or("action")?)?,
        json!({"create":{"_index":"keenetic-logs-2026.11.06"}})
    );
    Ok(())
}

#[test]
fn sink_queue_overflow_drops_oldest_and_counts_it() -> TestResult {
    let metrics = SelfMetrics::new("queue-test")?;
    let registry = Registry::new();
    metrics.register(&registry)?;
    let timestamp = at(2026, 11, 7, 12, 0, 1)?;
    let capacity = NonZeroUsize::new(2).ok_or("capacity")?;
    let mut queue = Pending::new("loki-0".to_owned(), capacity, metrics);

    queue.push(record(1, timestamp, "oldest"));
    queue.push(record(2, timestamp, "retained"));
    queue.push(record(3, timestamp, "newest"));

    assert_eq!(
        queue.records().map(|item| item.id).collect::<Vec<_>>(),
        [2, 3]
    );
    let exposition = TextEncoder::new().encode_to_string(&registry.gather())?;
    assert!(exposition.lines().any(|line| {
        line == "kcc_log_records_dropped_total{reason=\"overflow\",sink=\"loki-0\"} 1"
    }));
    Ok(())
}

fn record(id: u64, ts: NaiveDateTime, message: &str) -> LogRecord {
    LogRecord::new(
        "home".to_owned(),
        id,
        ts,
        "info".to_owned(),
        message.to_owned(),
    )
    .with_process("ndm".to_owned(), 7)
}

#[tokio::test(start_paused = true)]
async fn collector_owns_one_stream_and_emits_each_id_once() -> TestResult {
    let directory = TempDir::new()?;
    let password = directory.path().join("password");
    fs::write(&password, DEFAULT_PASSWORD)?;
    let router = FakeRouter::builder(Profile::default()).build()?;
    router.insert_log(
        10,
        json!({"message":{"label":"I","message":"[Jan 01 00:00:00] first"}}),
    );
    let (address, handle) = router.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let client = client(address).await?;
    let config = Config::from_toml_str("[logs]\nenabled = true\n")?;
    config.validate()?;
    let collector = LogCollector::start(
        "fake",
        client,
        &config.logs,
        SelfMetrics::new("collector-test")?,
    )?;
    let mut web_reader = collector.subscribe();
    let mut sink_reader = collector.subscribe();

    sleep(Duration::from_secs(5)).await;
    let web = timeout(Duration::from_secs(1), web_reader.recv()).await??;
    let sink = timeout(Duration::from_secs(1), sink_reader.recv()).await??;
    assert_eq!((web.id, sink.id), (10, 10));
    assert_eq!(
        handle.log_streams(),
        1,
        "subscribers share the collector stream"
    );

    handle.insert_log(
        10,
        json!({"message":{"label":"I","message":"[Jan 01 00:00:00] replay"}}),
    );
    handle.insert_log(
        11,
        json!({"message":{"label":"I","message":"[Jan 01 00:00:01] second"}}),
    );
    sleep(Duration::from_secs(5)).await;
    let next = timeout(Duration::from_secs(1), web_reader.recv()).await??;
    assert_eq!(next.id, 11, "replayed id is suppressed");
    assert_eq!(handle.log_streams(), 1);

    collector.shutdown().await?;
    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn runtime_forwards_fake_router_records_to_fake_loki() -> TestResult {
    let router = FakeRouter::builder(Profile::default()).build()?;
    router.insert_log(
        21,
        json!({"message":{"label":"I","message":"[Jan 01 00:00:00] forwarded"}}),
    );
    let (address, handle) = router.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let fake_loki = FakeLoki::spawn().await?;
    let config = Config::from_toml_str(&format!(
        "[logs]\nenabled = true\n\n[[logs.sinks]]\nkind = \"loki\"\nurl = \"{}\"\n",
        fake_loki.url()
    ))?;
    config.validate()?;
    let metrics = SelfMetrics::new("runtime-test")?;
    let runtime = LogService::start(
        vec![("fake".to_owned(), client(address).await?)],
        &config.logs,
        metrics,
    )
    .await?;
    let mut page = runtime.subscribe("fake").ok_or("collector")?;

    sleep(Duration::from_secs(5)).await;
    assert_eq!(timeout(Duration::from_secs(1), page.recv()).await??.id, 21);
    sleep(Duration::from_secs(2)).await;
    runtime.shutdown().await;

    assert_eq!(handle.log_streams(), 1);
    assert_eq!(fake_loki.requests().len(), 1);
    fake_loki.shutdown().await?;
    handle.shutdown().await?;
    Ok(())
}
