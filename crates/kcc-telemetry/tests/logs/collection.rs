//! Collector contracts: malformed records, router timestamps, level labels, shutdown fan-out.

use core::{error::Error, time::Duration};
use std::sync::Arc;

use kcc_app::settings::Config;
use kcc_telemetry::{
    logs::{runtime::Service as LogService, types::LogRecord},
    metrics::instrumentation::SelfMetrics,
};
use kcc_testkit::{
    FakeRouter, Handle, fake_elasticsearch::FakeElasticsearch, fake_loki::FakeLoki, model::Profile,
};
use prometheus::{Registry, TextEncoder};
use serde_json::{Value, json};
use tokio::{
    sync::broadcast::Receiver,
    time::{Instant, timeout},
};

use super::{Endpoint, TestResult, client, serve};

/// Longest virtual wait for a collector to read the router.
const READ_BOUND: Duration = Duration::from_secs(60);

/// A fake router serving `logs`, keyed by record id.
// cancel-safe: dropping it drops the fake's handle, which stops the fake.
async fn router_with(logs: Vec<(u64, Value)>) -> Result<(Endpoint, Handle), Box<dyn Error>> {
    let router = FakeRouter::builder(Profile::default()).build()?;
    for (id, record) in logs {
        router.insert_log(id, record);
    }
    serve(router).await
}

/// One router record as the firmware writes it.
fn entry(level: Option<&str>, message: &str) -> Value {
    let mut body = json!({"label": "I", "message": message});
    if let (Some(text), Some(fields)) = (level, body.as_object_mut()) {
        drop(fields.insert("level".to_owned(), json!(text)));
    }
    json!({ "message": body })
}

/// The ids of the next `count` records a reader receives.
async fn received(
    reader: &mut Receiver<LogRecord>,
    count: usize,
) -> Result<Vec<u64>, Box<dyn Error>> {
    let mut ids = Vec::new();
    while ids.len() < count {
        ids.push(timeout(READ_BOUND, reader.recv()).await??.id);
    }
    Ok(ids)
}

/// The decoded JSON bodies of every Loki push the fake received.
fn loki_streams(fake: &FakeLoki) -> Result<Vec<Value>, Box<dyn Error>> {
    let mut streams = Vec::new();
    for request in fake.requests() {
        let payload: Value = serde_json::from_slice(request.body())?;
        streams.extend(
            payload
                .get("streams")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        );
    }
    Ok(streams)
}

/// G-10: one malformed router record among good ones neither blocks nor hides them: the good
/// records are forwarded and the bad one is counted as a `parse` drop.
#[tokio::test(start_paused = true)]
async fn malformed_record_is_counted_and_the_others_are_forwarded() -> TestResult {
    let (router, handle) = router_with(vec![
        (1, entry(None, "[Jan 01 00:00:00] first")),
        (2, entry(None, "no bracket timestamp")),
        (3, entry(None, "[Jan 01 00:00:01] third")),
    ])
    .await?;
    let fake = FakeLoki::spawn().await?;
    let config = Config::from_toml_str(&format!(
        "[logs]\nenabled = true\n\n[[logs.sinks]]\nkind = \"loki\"\nurl = \"{}\"\n",
        fake.url()
    ))?;
    config.validate()?;
    let metrics = SelfMetrics::new("parse-test")?;
    let registry = Registry::new();
    metrics.register(&registry)?;
    let runtime = LogService::start(
        vec![("fake".to_owned(), client(&router).await?)],
        &config.logs,
        metrics,
    )
    .await?;
    let mut page = runtime.subscribe("fake").ok_or("collector")?;

    let ids = received(&mut page, 2).await?;
    runtime.shutdown().await;

    assert_eq!(ids, [1, 3]);
    let forwarded = loki_streams(&fake)?
        .iter()
        .filter_map(|stream| stream.get("values").and_then(Value::as_array))
        .map(Vec::len)
        .sum::<usize>();
    assert_eq!(forwarded, 2);
    let exposition = TextEncoder::new().encode_to_string(&registry.gather())?;
    assert!(
        exposition.contains("kcc_log_records_dropped_total{reason=\"parse\",sink=\"collector\"} 1"),
        "{exposition}"
    );
    fake.shutdown().await?;
    handle.shutdown().await?;
    Ok(())
}

/// G-11: the router writes its local wall-clock time without an offset; the forwarded
/// document carries that naive local time and does not claim it is UTC.
#[tokio::test(start_paused = true)]
async fn forwarded_timestamp_is_naive_local_time() -> TestResult {
    let (router, handle) =
        router_with(vec![(5, entry(None, "[Jan 01 00:00:00] local clock"))]).await?;
    let fake = FakeElasticsearch::spawn().await?;
    let config = Config::from_toml_str(&format!(
        "[logs]\nenabled = true\n\n[[logs.sinks]]\nkind = \"elasticsearch\"\nurl = \"{}\"\n",
        fake.url()
    ))?;
    config.validate()?;
    let runtime = LogService::start(
        vec![("fake".to_owned(), client(&router).await?)],
        &config.logs,
        SelfMetrics::new("time-test")?,
    )
    .await?;
    let mut page = runtime.subscribe("fake").ok_or("collector")?;

    assert_eq!(received(&mut page, 1).await?, [5]);
    runtime.shutdown().await;

    let requests = fake.requests();
    let request = requests.first().ok_or("bulk request")?;
    let line = request
        .body()
        .split(|byte| *byte == b'\n')
        .nth(1)
        .ok_or("document line")?;
    let document: Value = serde_json::from_slice(line)?;
    let stamp = document
        .get("@timestamp")
        .and_then(Value::as_str)
        .ok_or("@timestamp")?;
    assert!(stamp.ends_with("-01-01T00:00:00"), "{stamp}");
    fake.shutdown().await?;
    handle.shutdown().await?;
    Ok(())
}

/// G-24: a `level` text the router invents becomes the fixed `other` label instead of a new
/// Loki stream label value.
#[tokio::test(start_paused = true)]
async fn unknown_router_level_becomes_other() -> TestResult {
    let (router, handle) = router_with(vec![
        (
            7,
            entry(Some("Hostile{label=\"x\"}"), "[Jan 01 00:00:00] odd"),
        ),
        (8, entry(Some("Error"), "[Jan 01 00:00:01] known")),
    ])
    .await?;
    let fake = FakeLoki::spawn().await?;
    let config = Config::from_toml_str(&format!(
        "[logs]\nenabled = true\n\n[[logs.sinks]]\nkind = \"loki\"\nurl = \"{}\"\n",
        fake.url()
    ))?;
    config.validate()?;
    let runtime = LogService::start(
        vec![("fake".to_owned(), client(&router).await?)],
        &config.logs,
        SelfMetrics::new("level-test")?,
    )
    .await?;
    let mut page = runtime.subscribe("fake").ok_or("collector")?;

    assert_eq!(received(&mut page, 2).await?, [7, 8]);
    runtime.shutdown().await;

    let mut levels = loki_streams(&fake)?
        .iter()
        .filter_map(|stream| stream.pointer("/stream/level").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    levels.sort();
    assert_eq!(levels, ["error", "other"]);
    fake.shutdown().await?;
    handle.shutdown().await?;
    Ok(())
}

/// G-12: collectors waiting out their poll interval stop together when the service shuts
/// down, within one bound rather than one interval per router.
#[tokio::test(start_paused = true)]
async fn polling_collectors_stop_together_without_waiting_out_their_interval() -> TestResult {
    let (router, handle) = router_with(vec![(1, entry(None, "[Jan 01 00:00:00] seen"))]).await?;
    let config = Config::from_toml_str("[logs]\nenabled = true\nmode = \"poll\"\n")?;
    config.validate()?;
    let shared = client(&router).await?;
    let names = ["first", "second", "third"];
    let runtime = LogService::start(
        names
            .iter()
            .map(|name| ((*name).to_owned(), Arc::clone(&shared)))
            .collect(),
        &config.logs,
        SelfMetrics::new("fanout-test")?,
    )
    .await?;
    let mut pages = names
        .iter()
        .map(|name| runtime.subscribe(name).ok_or("collector"))
        .collect::<Result<Vec<_>, _>>()?;
    for page in &mut pages {
        assert_eq!(received(page, 1).await?, [1]);
    }

    let started = Instant::now();
    runtime.shutdown().await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < config.logs.poll_interval,
        "shutdown took {elapsed:?}, poll interval {:?}",
        config.logs.poll_interval
    );
    handle.shutdown().await?;
    Ok(())
}
