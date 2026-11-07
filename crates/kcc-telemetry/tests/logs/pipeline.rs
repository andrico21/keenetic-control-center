//! End-to-end queue, batching, item classification, and credential-redaction contracts.

use core::{error::Error, time::Duration};
use std::{
    fs, io,
    sync::{Arc, Mutex},
};

use chrono::{FixedOffset, TimeZone as _};
use kcc_app::settings::Config;
use kcc_telemetry::{logs::pipeline::LogForwarder, metrics::instrumentation::SelfMetrics};
use kcc_testkit::{
    fake_elasticsearch::{FakeElasticsearch, Fault as ElasticsearchFault},
    fake_loki::FakeLoki,
};
use prometheus::{Registry, TextEncoder};
use tempfile::TempDir;
use tokio::time::advance;
use tracing::{Level, subscriber::set_default};
use tracing_subscriber::fmt::MakeWriter;

use super::{TestResult, record};

#[tokio::test(start_paused = true)]
async fn search_item_error_drops_only_the_failing_record() -> TestResult {
    let fake =
        FakeElasticsearch::spawn_with_faults(vec![ElasticsearchFault::MapperParsing { item: 1 }])
            .await?;
    let config = Config::from_toml_str(&format!(
        "[logs]\nenabled = true\n\n[[logs.sinks]]\nkind = \"elasticsearch\"\nurl = \"{}\"\n",
        fake.url()
    ))?;
    config.validate()?;
    let metrics = SelfMetrics::new("pipeline-test")?;
    let registry = Registry::new();
    metrics.register(&registry)?;
    let pipeline = LogForwarder::start(&config.logs, metrics).await?;
    let timestamp = timestamp()?;
    for (id, message) in [(1, "first"), (2, "bad"), (3, "last")] {
        pipeline.push(&record(id, timestamp, message));
    }

    advance(Duration::from_secs(2)).await;
    pipeline.shutdown().await;

    assert_eq!(fake.requests().len(), 1);
    let exposition = TextEncoder::new().encode_to_string(&registry.gather())?;
    assert!(exposition.contains("kcc_log_records_forwarded_total{sink=\"search-0\"} 2"));
    assert!(
        exposition
            .contains("kcc_log_records_dropped_total{reason=\"permanent\",sink=\"search-0\"} 1")
    );
    fake.shutdown().await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn record_bound_splits_one_thousand_and_one_records() -> TestResult {
    let fake = FakeLoki::spawn().await?;
    let config = Config::from_toml_str(&format!(
        "[logs]\nenabled = true\n\n[[logs.sinks]]\nkind = \"loki\"\nurl = \"{}\"\n",
        fake.url()
    ))?;
    config.validate()?;
    let metrics = SelfMetrics::new("batch-test")?;
    let pipeline = LogForwarder::start(&config.logs, metrics).await?;
    let timestamp = timestamp()?;
    for id in 0..=1_000 {
        pipeline.push(&record(id, timestamp, "bounded"));
    }

    pipeline.shutdown().await;

    assert_eq!(fake.requests().len(), 2);
    fake.shutdown().await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn trace_and_debug_never_include_sink_password_or_api_key() -> TestResult {
    let fake = FakeElasticsearch::spawn().await?;
    let directory = TempDir::new()?;
    let key = directory.path().join("api-key");
    fs::write(&key, "trace-secret-api-key\n")?;
    let config = Config::from_toml_str(&format!(
        "[logs]\nenabled = true\n\n[[logs.sinks]]\nkind = \"elasticsearch\"\nurl = \"{}\"\napi_key_file = {key:?}\n",
        fake.url()
    ))?;
    config.validate()?;
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_writer(capture.clone())
        .finish();
    let _guard = set_default(subscriber);
    let metrics = SelfMetrics::new("trace-test")?;
    let pipeline = LogForwarder::start(&config.logs, metrics).await?;
    assert!(!format!("{pipeline:?}").contains("trace-secret-api-key"));
    pipeline.push(&record(7, timestamp()?, "ordinary record"));

    pipeline.shutdown().await;

    let output = capture.text();
    assert!(!output.contains("trace-secret-api-key"));
    fake.shutdown().await?;
    Ok(())
}

fn timestamp() -> Result<chrono::DateTime<FixedOffset>, Box<dyn Error>> {
    FixedOffset::east_opt(0)
        .and_then(|offset| offset.with_ymd_and_hms(2026, 11, 7, 12, 0, 1).single())
        .ok_or_else(|| "timestamp".into())
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn text(&self) -> String {
        let bytes = match self.0.lock() {
            Ok(bytes) => bytes.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl<'writer> MakeWriter<'writer> for Capture {
    type Writer = CaptureWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        CaptureWriter(Arc::clone(&self.0))
    }
}

struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.0.lock() {
            Ok(mut bytes) => bytes.extend_from_slice(buf),
            Err(poisoned) => poisoned.into_inner().extend_from_slice(buf),
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
