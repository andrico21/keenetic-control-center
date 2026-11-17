//! The delivery loop of one log sink worker: batching, retries and shutdown.

use alloc::sync::Arc;
use core::time::Duration;
use std::sync::{Mutex, MutexGuard};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::{
    batch::{MAX_RECORDS, Refused, select},
    destination::Sink,
    elastic_sink::ElasticsearchClient,
    format,
    queue::Pending,
    retry::{Clock, delay},
    sink::{DeliveryError, LokiClient},
    types::LogRecord,
};
use crate::metrics::instrumentation::SelfMetrics;

/// Maximum partial-batch wait.
const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

/// The two shutdown signals of one worker.
#[derive(Debug)]
pub(super) struct Stop {
    /// Stop waiting for more records and deliver what is queued.
    flush: CancellationToken,
    /// Give up delivering: count what is left as dropped at shutdown and return.
    abort: CancellationToken,
}

impl Stop {
    /// Signals taken from the forwarder's `flush` and `abort` tokens.
    pub(super) const fn new(flush: CancellationToken, abort: CancellationToken) -> Self {
        Self { flush, abort }
    }
}

/// A delivery cut short by [`Stop::abort`]; its records are already counted.
struct Aborted;

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
    stop: Stop,
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
        stop: Stop,
    ) -> Self {
        Self {
            name,
            sink,
            queue,
            notify,
            metrics,
            clock,
            stop,
        }
    }
}

/// Runs one sink worker until it has flushed its queue after [`Stop::flush`], or until
/// [`Stop::abort`], after which every undelivered record is counted as dropped at shutdown.
// cancel-safe: queued records stay in the shared queue; only an in-flight batch is lost, and
// the forwarder never drops this future (it signals `Stop` instead).
pub(super) async fn worker(worker: Worker) {
    let flush = &worker.stop.flush;
    loop {
        if lock(&worker.queue).is_empty() {
            tokio::select! { () = flush.cancelled() => return, () = worker.notify.notified() => {} }
        }
        if !flush.is_cancelled() {
            tokio::select! { () = flush.cancelled() => {}, () = worker.clock.wait(FLUSH_INTERVAL) => {}, () = worker.notify.notified(), if lock(&worker.queue).records().len() >= MAX_RECORDS => {} }
        }
        while let Some(batch) = take_batch(&worker) {
            if deliver(&worker, batch).await.is_err() {
                let left = lock(&worker.queue).clear();
                dropped(&worker, "shutdown", left);
                return;
            }
            if !flush.is_cancelled() {
                break;
            }
        }
        if flush.is_cancelled() && lock(&worker.queue).is_empty() {
            return;
        }
    }
}

/// Selects the next non-empty batch, counting the records refused on the way.
fn take_batch(worker: &Worker) -> Option<Vec<LogRecord>> {
    loop {
        let batch = select(
            &worker.queue,
            |record| worker.sink.record_len(record),
            |refused| {
                let reason = match refused {
                    Refused::Oversize => "oversize",
                    Refused::Unencodable => "encode",
                };
                dropped(worker, reason, 1);
            },
        );
        if !batch.is_empty() {
            return Some(batch);
        }
        if lock(&worker.queue).is_empty() {
            return None;
        }
    }
}

/// Delivers one selected batch.
///
/// # Errors
///
/// [`Aborted`] when [`Stop::abort`] cut the delivery short; the batch is counted.
// cancel-safe: every await inside is raced against `Stop::abort`, which counts the batch.
async fn deliver(worker: &Worker, batch: Vec<LogRecord>) -> Result<(), Aborted> {
    match &worker.sink {
        Sink::Loki(client) => deliver_loki(worker, client, &batch).await,
        Sink::Search(client) => deliver_search(worker, client, batch).await,
        Sink::Stdout => {
            deliver_stdout(worker, &batch);
            Ok(())
        }
    }
}
/// Delivers one Loki batch with retries.
///
/// # Errors
///
/// [`Aborted`] when [`Stop::abort`] cut the delivery short; the batch is counted.
// cancel-safe: see `deliver`.
async fn deliver_loki(
    worker: &Worker,
    client: &LokiClient,
    batch: &[LogRecord],
) -> Result<(), Aborted> {
    let mut attempt = 0_u32;
    loop {
        let sent = tokio::select! {
            biased;
            () = worker.stop.abort.cancelled() => return aborted(worker, batch.len()),
            sent = client.send(batch) => sent,
        };
        match sent {
            Ok(()) => {
                forwarded(worker, batch.len());
                return Ok(());
            }
            Err(error) if error.is_retriable() => {
                worker.metrics.log_retry(&worker.name);
                pause(worker, delay(attempt, error.retry_after()), batch.len()).await?;
                attempt = attempt.saturating_add(1);
            }
            Err(DeliveryError::PartiallyAccepted { rejected }) => {
                tracing::warn!(sink = %worker.name, rejected, sent = batch.len(), "log sink refused part of a push");
                forwarded(worker, batch.len().saturating_sub(rejected));
                dropped(worker, "permanent", rejected);
                return Ok(());
            }
            Err(error) => {
                tracing::warn!(sink = %worker.name, %error, sent = batch.len(), "log sink refused a push");
                dropped(worker, "permanent", batch.len());
                return Ok(());
            }
        }
    }
}
/// Delivers search items with selective retries.
///
/// # Errors
///
/// [`Aborted`] when [`Stop::abort`] cut the delivery short; the records left are counted.
// cancel-safe: see `deliver`.
async fn deliver_search(
    worker: &Worker,
    client: &ElasticsearchClient,
    mut batch: Vec<LogRecord>,
) -> Result<(), Aborted> {
    let mut attempt = 0_u32;
    loop {
        let sent = tokio::select! {
            biased;
            () = worker.stop.abort.cancelled() => return aborted(worker, batch.len()),
            sent = client.send(&batch) => sent,
        };
        match sent {
            Ok(outcome) => {
                forwarded(worker, outcome.accepted);
                dropped(worker, "permanent", outcome.dropped.len());
                if outcome.retriable.is_empty() {
                    return Ok(());
                }
                batch = batch
                    .into_iter()
                    .enumerate()
                    .filter_map(|(index, record)| {
                        outcome.retriable.contains(&index).then_some(record)
                    })
                    .collect();
                worker.metrics.log_retry(&worker.name);
                pause(worker, delay(attempt, None), batch.len()).await?;
                attempt = attempt.saturating_add(1);
            }
            Err(error) if error.is_retriable() => {
                worker.metrics.log_retry(&worker.name);
                pause(worker, delay(attempt, error.retry_after()), batch.len()).await?;
                attempt = attempt.saturating_add(1);
            }
            Err(_) => {
                dropped(worker, "permanent", batch.len());
                return Ok(());
            }
        }
    }
}
/// Waits before a retry.
///
/// # Errors
///
/// [`Aborted`] after counting the `pending` records when [`Stop::abort`] comes first.
// cancel-safe: a clock wait holds no state.
async fn pause(worker: &Worker, duration: Duration, pending: usize) -> Result<(), Aborted> {
    tokio::select! {
        biased;
        () = worker.stop.abort.cancelled() => aborted(worker, pending),
        () = worker.clock.wait(duration) => Ok(()),
    }
}
/// Counts the `pending` records of an aborted delivery.
///
/// # Errors
///
/// Always [`Aborted`].
fn aborted(worker: &Worker, pending: usize) -> Result<(), Aborted> {
    dropped(worker, "shutdown", pending);
    Err(Aborted)
}
/// Accounts for standard-output delivery.
fn deliver_stdout(worker: &Worker, batch: &[LogRecord]) {
    match format::stdout(batch) {
        Ok(payload) => {
            tracing::info!(sink = %worker.name, records = batch.len(), bytes = payload.len(), "router log batch written to stdout sink");
            forwarded(worker, batch.len());
        }
        Err(_) => dropped(worker, "encode", batch.len()),
    }
}
/// Counts accepted records.
fn forwarded(worker: &Worker, count: usize) {
    worker
        .metrics
        .log_records_forwarded(&worker.name, usize_u64(count));
}
/// Counts records lost for `reason`.
fn dropped(worker: &Worker, reason: &str, count: usize) {
    worker
        .metrics
        .log_records_dropped(&worker.name, reason, usize_u64(count));
}
/// Saturates a platform-sized count.
fn usize_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
/// Recovers poisoned queue state.
pub(super) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
