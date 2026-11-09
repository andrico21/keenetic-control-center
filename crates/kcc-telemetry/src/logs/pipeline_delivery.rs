//! Batch selection and delivery for one log sink worker.

use alloc::sync::Arc;
use core::{fmt, time::Duration};
use std::sync::{Mutex, MutexGuard};

use kcc_app::settings::{LogSinkConfig, SearchFlavor};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::{
    elastic_sink::ElasticsearchClient,
    format,
    queue::Pending,
    retry::{Clock, delay},
    sink::{DeliveryError, LokiClient},
    types::LogRecord,
};
use crate::metrics::instrumentation::SelfMetrics;

/// Maximum records per request.
const MAX_RECORDS: usize = 1_000;
/// Maximum bytes per request.
const MAX_BYTES: usize = 0x0010_0000;
/// Maximum partial-batch wait.
const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

/// Loaded destination adapter.
pub(super) enum Sink {
    /// Loki.
    Loki(LokiClient),
    /// Elasticsearch or `OpenSearch`.
    Search(ElasticsearchClient),
    /// Standard output.
    Stdout,
}
impl fmt::Debug for Sink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Loki(client) => f.debug_tuple("Loki").field(client).finish(),
            Self::Search(client) => f.debug_tuple("Search").field(client).finish(),
            Self::Stdout => f.write_str("Stdout"),
        }
    }
}
impl Sink {
    /// Loads one destination.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError`] when setup fails.
    pub(super) async fn load(config: &LogSinkConfig) -> Result<Self, DeliveryError> {
        match config {
            LogSinkConfig::Loki {
                url: _,
                tenant: _,
                basic_auth_user: _,
                password_file: _,
                bearer_token_file: _,
                ca_file: _,
                compress: _,
            } => Ok(Self::Loki(LokiClient::load(config).await?)),
            LogSinkConfig::Elasticsearch {
                url: _,
                flavor: _,
                target: _,
                basic_auth_user: _,
                password_file: _,
                api_key_file: _,
                ca_file: _,
                compress: _,
            } => Ok(Self::Search(ElasticsearchClient::load(config).await?)),
            LogSinkConfig::Stdout => Ok(Self::Stdout),
            _ => Err(DeliveryError::WrongKind),
        }
    }
    /// Measures one encoded request.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Payload`] when encoding fails.
    fn encoded_len(&self, records: &[LogRecord]) -> Result<usize, DeliveryError> {
        match self {
            Self::Loki(_) => format::loki(records),
            Self::Search(_) => format::bulk(records, SearchFlavor::Elasticsearch, None),
            Self::Stdout => format::stdout(records),
        }
        .map(|payload| payload.len())
        .map_err(|_error| DeliveryError::Payload)
    }
}

/// Immutable worker dependencies.
pub(super) struct Worker {
    /// Metric label.
    name: String,
    /// Loaded destination.
    sink: Sink,
    /// Pending records.
    queue: Arc<Mutex<Pending>>,
    /// Producer notification.
    notify: Arc<Notify>,
    /// Shared counters.
    metrics: Arc<SelfMetrics>,
    /// Retry clock.
    clock: Arc<dyn Clock>,
    /// Cooperative shutdown.
    cancellation: CancellationToken,
}

impl Worker {
    /// Creates one worker dependency set.
    pub(super) fn new(
        name: String,
        sink: Sink,
        queue: Arc<Mutex<Pending>>,
        notify: Arc<Notify>,
        metrics: Arc<SelfMetrics>,
        clock: Arc<dyn Clock>,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            name,
            sink,
            queue,
            notify,
            metrics,
            clock,
            cancellation,
        }
    }
}

/// Runs one sink worker.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "tokio::select expansion"
)]
pub(super) async fn worker(worker: Worker) {
    loop {
        if lock(&worker.queue).is_empty() {
            tokio::select! { () = worker.cancellation.cancelled() => return, () = worker.notify.notified() => {} }
        }
        if !worker.cancellation.is_cancelled() {
            tokio::select! { () = worker.cancellation.cancelled() => {}, () = worker.clock.wait(FLUSH_INTERVAL) => {}, () = worker.notify.notified(), if lock(&worker.queue).records().len() >= MAX_RECORDS => {} }
        }
        while let Some(batch) = take_batch(&worker) {
            deliver(&worker, batch).await;
            if !worker.cancellation.is_cancelled() {
                break;
            }
        }
        if worker.cancellation.is_cancelled() && lock(&worker.queue).is_empty() {
            return;
        }
    }
}

/// Selects one bounded batch.
fn take_batch(worker: &Worker) -> Option<Vec<LogRecord>> {
    let mut queue = lock(&worker.queue);
    let mut batch = Vec::new();
    while batch.len() < MAX_RECORDS {
        let Some(record) = queue.pop() else { break };
        batch.push(record);
        match worker.sink.encoded_len(&batch) {
            Ok(bytes) if bytes <= MAX_BYTES => {}
            Ok(_) if batch.len() == 1 => {
                worker
                    .metrics
                    .log_records_dropped(&worker.name, "oversize", 1);
                batch.clear();
            }
            Ok(_) => {
                if let Some(boundary) = batch.pop() {
                    queue.restore(boundary);
                }
                break;
            }
            Err(_) => {
                worker
                    .metrics
                    .log_records_dropped(&worker.name, "encode", 1);
                drop(batch.pop());
            }
        }
    }
    drop(queue);
    (!batch.is_empty()).then_some(batch)
}

/// Delivers one selected batch.
async fn deliver(worker: &Worker, batch: Vec<LogRecord>) {
    match &worker.sink {
        Sink::Loki(client) => deliver_loki(worker, client, &batch).await,
        Sink::Search(client) => deliver_search(worker, client, batch).await,
        Sink::Stdout => deliver_stdout(worker, &batch),
    }
}
/// Delivers one Loki batch with retries.
async fn deliver_loki(worker: &Worker, client: &LokiClient, batch: &[LogRecord]) {
    let mut attempt = 0_u32;
    loop {
        match client.send(batch).await {
            Ok(()) => {
                forwarded(worker, batch.len());
                return;
            }
            Err(error) if error.is_retriable() => {
                worker.metrics.log_retry(&worker.name);
                worker.clock.wait(delay(attempt, error.retry_after())).await;
                attempt = attempt.saturating_add(1);
            }
            Err(DeliveryError::PartiallyAccepted { rejected }) => {
                tracing::warn!(sink = %worker.name, rejected, sent = batch.len(), "log sink refused part of a push");
                forwarded(worker, batch.len().saturating_sub(rejected));
                dropped(worker, rejected);
                return;
            }
            Err(error) => {
                tracing::warn!(sink = %worker.name, %error, sent = batch.len(), "log sink refused a push");
                dropped(worker, batch.len());
                return;
            }
        }
    }
}
/// Delivers search items with selective retries.
async fn deliver_search(worker: &Worker, client: &ElasticsearchClient, mut batch: Vec<LogRecord>) {
    let mut attempt = 0_u32;
    loop {
        match client.send(&batch).await {
            Ok(outcome) => {
                forwarded(worker, outcome.accepted);
                dropped(worker, outcome.dropped.len());
                if outcome.retriable.is_empty() {
                    return;
                }
                batch = batch
                    .into_iter()
                    .enumerate()
                    .filter_map(|(index, record)| {
                        outcome.retriable.contains(&index).then_some(record)
                    })
                    .collect();
                worker.metrics.log_retry(&worker.name);
                worker.clock.wait(delay(attempt, None)).await;
                attempt = attempt.saturating_add(1);
            }
            Err(error) if error.is_retriable() => {
                worker.metrics.log_retry(&worker.name);
                worker.clock.wait(delay(attempt, error.retry_after())).await;
                attempt = attempt.saturating_add(1);
            }
            Err(_) => {
                dropped(worker, batch.len());
                return;
            }
        }
    }
}
/// Accounts for standard-output delivery.
fn deliver_stdout(worker: &Worker, batch: &[LogRecord]) {
    match format::stdout(batch) {
        Ok(payload) => {
            tracing::info!(sink = %worker.name, records = batch.len(), bytes = payload.len(), "router log batch written to stdout sink");
            forwarded(worker, batch.len());
        }
        Err(_) => {
            worker
                .metrics
                .log_records_dropped(&worker.name, "encode", usize_u64(batch.len()));
        }
    }
}
/// Counts accepted records.
fn forwarded(worker: &Worker, count: usize) {
    worker
        .metrics
        .log_records_forwarded(&worker.name, usize_u64(count));
}
/// Counts permanently rejected records.
fn dropped(worker: &Worker, count: usize) {
    worker
        .metrics
        .log_records_dropped(&worker.name, "permanent", usize_u64(count));
}
/// Saturates a platform-sized count.
fn usize_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
/// Recovers poisoned queue state.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
