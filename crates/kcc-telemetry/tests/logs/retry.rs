//! Log destination retry policy contracts.

use core::{
    error::Error,
    fmt,
    future::ready,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use std::{
    io,
    sync::{Arc, Mutex},
};

use kcc_app::settings::Config;
use kcc_telemetry::{
    logs::{pipeline::LogForwarder, retry::Clock},
    metrics::instrumentation::SelfMetrics,
};
use kcc_testkit::fake_loki::{FakeLoki, Fault};
use prometheus::{Registry, TextEncoder};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    task::JoinHandle,
};

use super::{TestResult, pipeline::complete, record};

#[derive(Default)]
struct RecordingClock {
    waits: Mutex<Vec<Duration>>,
}

impl fmt::Debug for RecordingClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordingClock")
    }
}

impl Clock for RecordingClock {
    fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        match self.waits.lock() {
            Ok(mut waits) => waits.push(duration),
            Err(poisoned) => poisoned.into_inner().push(duration),
        }
        Box::pin(ready(()))
    }
}

#[tokio::test]
async fn retry_after_delays_loki_retry_by_at_least_two_seconds() -> TestResult {
    let fake =
        FakeLoki::spawn_with_faults(vec![Fault::TooManyRequests(Duration::from_secs(2))]).await?;
    let config = Config::from_toml_str(&format!(
        "[logs]\nenabled = true\n\n[[logs.sinks]]\nkind = \"loki\"\nurl = \"{}\"\n",
        fake.url()
    ))?;
    config.validate()?;
    let timestamp = super::at(2026, 11, 7, 12, 0, 1)?;
    let clock = Arc::new(RecordingClock::default());
    let metrics = SelfMetrics::new("retry-test")?;
    let shared: Arc<dyn Clock> = Arc::<RecordingClock>::clone(&clock);
    let pipeline = LogForwarder::start_with_clock(&config.logs, metrics, shared).await?;

    pipeline.push(&record(13, timestamp, "retry-after"));
    pipeline.shutdown().await;

    let waits = match clock.waits.lock() {
        Ok(waits) => waits.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    assert_eq!(waits, [Duration::from_secs(2)]);
    assert_eq!(fake.requests().len(), 2);
    fake.shutdown().await?;
    Ok(())
}

/// A loopback sink that closes its first connection without an answer and answers every
/// later request with `answer`; returns its URL, the accepted-connection count and its task.
async fn flaky_sink(
    answer: String,
) -> Result<(String, Arc<AtomicUsize>, JoinHandle<io::Result<()>>), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _peer) = listener.accept().await?;
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                drop(stream);
                continue;
            }
            let mut request = Vec::new();
            let mut chunk = [0_u8; 4096];
            while !complete(&request) {
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    break;
                }
                request.extend_from_slice(chunk.get(..read).unwrap_or_default());
            }
            stream.write_all(answer.as_bytes()).await?;
            stream.shutdown().await?;
        }
    });
    Ok((url, accepted, task))
}

/// Pushes one record through a forwarder for `sink` (a `[[logs.sinks]]` body) on a clock that
/// records its waits; returns the waits and the metric exposition after shutdown.
async fn deliver_once(sink: &str) -> Result<(Vec<Duration>, String), Box<dyn Error>> {
    let config =
        Config::from_toml_str(&format!("[logs]\nenabled = true\n\n[[logs.sinks]]\n{sink}"))?;
    config.validate()?;
    let clock = Arc::new(RecordingClock::default());
    let metrics = SelfMetrics::new("transport-retry-test")?;
    let registry = Registry::new();
    metrics.register(&registry)?;
    let shared: Arc<dyn Clock> = Arc::<RecordingClock>::clone(&clock);
    let pipeline = LogForwarder::start_with_clock(&config.logs, metrics, shared).await?;
    let timestamp = super::at(2026, 11, 7, 12, 0, 1)?;

    pipeline.push(&record(31, timestamp, "after a reset"));
    pipeline.shutdown().await;

    let waits = match clock.waits.lock() {
        Ok(waits) => waits.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    Ok((
        waits,
        TextEncoder::new().encode_to_string(&registry.gather())?,
    ))
}

/// G-08: a Loki connection reset is retried with the 429/5xx backoff, and the batch is
/// delivered once the sink answers.
#[tokio::test]
async fn loki_transport_error_is_retried_with_backoff() -> TestResult {
    let (url, accepted, task) =
        flaky_sink("HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n".to_owned()).await?;

    let (waits, exposition) = deliver_once(&format!("kind = \"loki\"\nurl = \"{url}\"\n")).await?;

    task.abort();
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "one failed and one delivered attempt"
    );
    assert_eq!(waits, [Duration::from_secs(1)]);
    assert!(
        exposition.contains("kcc_log_records_forwarded_total{sink=\"loki-0\"} 1"),
        "{exposition}"
    );
    assert!(
        !exposition.contains("kcc_log_records_dropped_total{"),
        "{exposition}"
    );
    Ok(())
}

/// G-08: an Elasticsearch connection reset is retried with the same backoff.
#[tokio::test]
async fn search_transport_error_is_retried_with_backoff() -> TestResult {
    let reply = r#"{"errors":false,"items":[{"create":{"status":201}}]}"#;
    let (url, accepted, task) = flaky_sink(format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
        reply.len()
    ))
    .await?;

    let (waits, exposition) =
        deliver_once(&format!("kind = \"elasticsearch\"\nurl = \"{url}\"\n")).await?;

    task.abort();
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "one failed and one delivered attempt"
    );
    assert_eq!(waits, [Duration::from_secs(1)]);
    assert!(
        exposition.contains("kcc_log_records_forwarded_total{sink=\"search-0\"} 1"),
        "{exposition}"
    );
    assert!(
        !exposition
            .contains("kcc_log_records_dropped_total{reason=\"permanent\",sink=\"search-0\"} 1"),
        "{exposition}"
    );
    Ok(())
}
