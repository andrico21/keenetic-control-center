//! Bounds on a log destination that hangs, keeps failing, or answers too much.

use core::{error::Error, time::Duration};
use std::io;

use kcc_app::settings::{Config, LogSinkConfig};
use kcc_telemetry::{
    logs::{
        elastic_sink::{BulkError, ElasticsearchClient},
        pipeline::LogForwarder,
        sink::{DeliveryError, LokiClient},
        types::LogRecord,
    },
    metrics::instrumentation::SelfMetrics,
};
use kcc_testkit::fake_loki::{FakeLoki, Fault};
use prometheus::{Registry, TextEncoder};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    task::JoinHandle,
    time::{Instant, timeout},
};

use super::{TestResult, pipeline::complete, record};

/// Longest per-request time a sink client may take, connection included.
const REQUEST_BOUND: Duration = Duration::from_secs(30);
/// The flush time `LogForwarder::shutdown` grants before it gives up.
const FLUSH_BOUND: Duration = Duration::from_secs(10);
/// A virtual wait far longer than any bound under test.
const NEVER: Duration = Duration::from_secs(3_600);

/// A listener that completes TCP handshakes in its backlog and never answers.
async fn silent_sink() -> Result<(String, TcpListener), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    Ok((format!("http://{}", listener.local_addr()?), listener))
}

/// The one configured sink of a `[[logs.sinks]]` body.
fn sink_config(body: &str) -> Result<LogSinkConfig, Box<dyn Error>> {
    let config =
        Config::from_toml_str(&format!("[logs]\nenabled = true\n\n[[logs.sinks]]\n{body}"))?;
    config.validate()?;
    Ok(config.logs.sinks.first().ok_or("sink")?.clone())
}

/// One record to send.
fn one() -> Result<[LogRecord; 1], Box<dyn Error>> {
    let timestamp = super::at(2026, 11, 7, 12, 0, 1)?;
    Ok([record(41, timestamp, "bounded")])
}

/// G-09, SEC2-14: a Loki push to a sink that never answers ends with a transport error at
/// the request timeout instead of hanging.
#[tokio::test(start_paused = true)]
async fn loki_push_to_a_silent_sink_ends_at_the_request_timeout() -> TestResult {
    let (url, _listener) = silent_sink().await?;
    let sink = LokiClient::load(&sink_config(&format!(
        "kind = \"loki\"\nurl = \"{url}\"\n"
    ))?)
    .await?;
    let started = Instant::now();

    let outcome = timeout(NEVER, sink.send(&one()?)).await;

    assert!(
        matches!(outcome, Ok(Err(DeliveryError::Transport))),
        "{outcome:?}"
    );
    assert!(
        started.elapsed() <= REQUEST_BOUND,
        "{:?}",
        started.elapsed()
    );
    Ok(())
}

/// G-09, SEC2-14: a Bulk request to a sink that never answers ends with a transport error at
/// the request timeout instead of hanging.
#[tokio::test(start_paused = true)]
async fn bulk_request_to_a_silent_sink_ends_at_the_request_timeout() -> TestResult {
    let (url, _listener) = silent_sink().await?;
    let sink = ElasticsearchClient::load(&sink_config(&format!(
        "kind = \"elasticsearch\"\nurl = \"{url}\"\n"
    ))?)
    .await?;
    let started = Instant::now();

    let outcome = timeout(NEVER, sink.send(&one()?)).await;

    assert!(
        matches!(
            outcome,
            Ok(Err(BulkError::Delivery(DeliveryError::Transport)))
        ),
        "{outcome:?}"
    );
    assert!(
        started.elapsed() <= REQUEST_BOUND,
        "{:?}",
        started.elapsed()
    );
    Ok(())
}

/// SEC2-14: a Bulk reply longer than the reply cap is cut there and treated as malformed,
/// instead of being read whole into memory.
#[tokio::test]
async fn oversized_bulk_reply_is_cut_at_the_cap() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let server: JoinHandle<io::Result<()>> = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await?;
        let mut request = Vec::new();
        let mut chunk = [0_u8; 4096];
        while !complete(&request) {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(chunk.get(..read).unwrap_or_default());
        }
        let mut reply = br#"{"errors":false,"items":[{"create":{"status":201}}]}"#.to_vec();
        reply.resize(reply.len().saturating_add(9 * 1024 * 1024), b' ');
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            reply.len()
        );
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(&reply).await
    });
    let sink = ElasticsearchClient::load(&sink_config(&format!(
        "kind = \"elasticsearch\"\nurl = \"{url}\"\n"
    ))?)
    .await?;

    let outcome = sink.send(&one()?).await;

    server.abort();
    assert!(matches!(outcome, Err(BulkError::Response)), "{outcome:?}");
    Ok(())
}

/// Starts a forwarder for `sink`, pushes `count` records and shuts it down; returns the
/// virtual shutdown time and the metric exposition.
async fn shut_down_with(sink: &str, count: u64) -> Result<(Duration, String), Box<dyn Error>> {
    let config =
        Config::from_toml_str(&format!("[logs]\nenabled = true\n\n[[logs.sinks]]\n{sink}"))?;
    config.validate()?;
    let metrics = SelfMetrics::new("shutdown-test")?;
    let registry = Registry::new();
    metrics.register(&registry)?;
    let pipeline = LogForwarder::start(&config.logs, metrics).await?;
    let [template] = one()?;
    for id in 0..count {
        pipeline.push(&record(id, template.ts, "pending at exit"));
    }
    let started = Instant::now();

    pipeline.shutdown().await;

    let elapsed = started.elapsed();
    Ok((
        elapsed,
        TextEncoder::new().encode_to_string(&registry.gather())?,
    ))
}

/// G-09: shutdown while a push to a silent sink is in flight ends at the flush deadline and
/// counts the in-flight batch and the records still queued as `shutdown` drops.
#[tokio::test(start_paused = true)]
async fn shutdown_counts_in_flight_and_queued_records_of_a_silent_sink() -> TestResult {
    let (url, _listener) = silent_sink().await?;

    let (elapsed, exposition) =
        shut_down_with(&format!("kind = \"loki\"\nurl = \"{url}\"\n"), 1_001).await?;

    assert!(elapsed <= FLUSH_BOUND, "{elapsed:?}");
    assert!(
        exposition
            .contains("kcc_log_records_dropped_total{reason=\"shutdown\",sink=\"loki-0\"} 1001"),
        "{exposition}"
    );
    Ok(())
}

/// G-09: shutdown while a batch waits out its retry backoff ends at the flush deadline and
/// counts that batch as `shutdown` drops.
#[tokio::test(start_paused = true)]
async fn shutdown_counts_a_batch_waiting_to_retry() -> TestResult {
    let fake = FakeLoki::spawn_with_faults(vec![Fault::InternalServerError; 16]).await?;

    let (elapsed, exposition) =
        shut_down_with(&format!("kind = \"loki\"\nurl = \"{}\"\n", fake.url()), 3).await?;

    assert!(elapsed <= FLUSH_BOUND, "{elapsed:?}");
    assert!(
        exposition.contains("kcc_log_records_dropped_total{reason=\"shutdown\",sink=\"loki-0\"} 3"),
        "{exposition}"
    );
    assert!(!exposition.contains("reason=\"permanent\""), "{exposition}");
    fake.shutdown().await?;
    Ok(())
}
