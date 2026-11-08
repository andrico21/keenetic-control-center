//! One-owner router log collection and subscriber fan-out.

use alloc::sync::Arc;
use core::time::Duration;
use std::time::SystemTime;

use chrono::{DateTime, FixedOffset, Utc};
use kcc_app::settings::{LogMode, LogsConfig};
use kcc_rci::{BackgroundHandle, RciBody, RciClient, RciError, RciPath};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::{
    sync::broadcast,
    task::{JoinError, JoinHandle},
    time,
};
use tokio_util::sync::CancellationToken;

use super::{
    dedupe::Window,
    parser,
    readers::{LogFeed, Recent, remember},
    redact,
    types::LogRecord,
};

/// Maximum records requested from one router read.
const MAX_LINES: u32 = 200;
/// Number of stream start failures before snapshot fallback.
const STREAM_FAILURES_BEFORE_FALLBACK: u8 = 2;

/// Collector construction or runtime failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LogError {
    /// The configured router id is not selected for collection.
    #[error("router is not selected for log collection")]
    RouterExcluded,
    /// The `show/log` resource path cannot be constructed.
    #[error("router log resource path is invalid")]
    Path,
    /// A router request failed.
    #[error(transparent)]
    Rci(#[from] RciError),
    /// A router response has the wrong body shape.
    #[error("router log response is malformed")]
    Response,
    /// A router log record is malformed.
    #[error(transparent)]
    Parse(#[from] parser::ParseError),
}

/// Collector-owned router log stream with queued fan-out to readers.
#[derive(Debug)]
#[non_exhaustive]
pub struct LogCollector {
    /// Subscriber sender.
    records: broadcast::Sender<LogRecord>,
    /// The latest records, for readers that subscribe later.
    recent: Recent,
    /// Cooperative task cancellation.
    cancellation: CancellationToken,
    /// Collection task.
    task: Option<JoinHandle<()>>,
}

impl LogCollector {
    /// Starts collection for one router.
    ///
    /// # Errors
    ///
    /// Returns [`LogError::RouterExcluded`] when collection is disabled or the
    /// router is outside the configured selection, and [`LogError::Path`] for an
    /// impossible built-in path.
    #[inline]
    pub fn start(
        router: &str,
        client: Arc<RciClient>,
        config: &LogsConfig,
    ) -> Result<Self, LogError> {
        if !config.enabled
            || (!config.routers.is_empty() && !config.routers.iter().any(|name| name == router))
        {
            return Err(LogError::RouterExcluded);
        }
        let path = RciPath::from_segments(["show", "log"]).map_err(|_error| LogError::Path)?;
        let (records, _) = broadcast::channel(1024);
        let recent = Recent::default();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(run(Collection {
            router: router.to_owned(),
            client,
            path,
            mode: config.mode,
            stream_interval: config.stream_interval,
            poll_interval: config.poll_interval,
            redact_macs: config.redact_macs,
            records: records.clone(),
            recent: Arc::clone(&recent),
            cancellation: cancellation.child_token(),
        }));
        Ok(Self {
            records,
            recent,
            cancellation,
            task: Some(task),
        })
    }

    /// Subscribes to records already parsed and deduplicated by this collector.
    #[inline]
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<LogRecord> {
        self.records.subscribe()
    }

    /// A reader's view of this collector: its latest records and new ones as they come.
    #[inline]
    #[must_use]
    pub fn feed(&self) -> LogFeed {
        LogFeed::new(&self.records, Arc::clone(&self.recent))
    }

    /// Stops collection and waits for remote stream cleanup.
    ///
    /// # Errors
    ///
    /// Returns the task join error if the collector panicked.
    ///
    /// # Cancel safety
    ///
    /// Once cancellation is sent, dropping this future loses the task result but the task
    /// continues remote cleanup.
    #[inline]
    pub async fn shutdown(mut self) -> Result<(), JoinError> {
        self.cancellation.cancel();
        let Some(task) = self.task.take() else {
            return Ok(());
        };
        task.await
    }
}

impl Drop for LogCollector {
    #[inline]
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

/// Immutable inputs owned by the collection task.
#[derive(Debug)]
struct Collection {
    /// Router profile id.
    router: String,
    /// Shared request engine.
    client: Arc<RciClient>,
    /// Built-in `show/log` path.
    path: RciPath,
    /// Configured preferred mode.
    mode: LogMode,
    /// Stream read interval.
    stream_interval: Duration,
    /// Snapshot read interval.
    poll_interval: Duration,
    /// Subscriber sender.
    records: broadcast::Sender<LogRecord>,
    /// The latest records, kept before each record is sent.
    recent: Recent,
    /// Redact hardware addresses before fan-out.
    redact_macs: bool,
    /// Cooperative shutdown.
    cancellation: CancellationToken,
}

/// Runs the configured mode until cancellation.
// cancel-safe: every loop iteration either performs read-only I/O or owns stream cleanup.
async fn run(collection: Collection) {
    let mut dedupe = Window::default();
    match collection.mode {
        LogMode::Poll => poll_loop(&collection, &mut dedupe).await,
        LogMode::Stream => stream_loop(&collection, &mut dedupe).await,
        _ => {}
    }
}

/// Polls bounded snapshots until cancellation.
// cancel-safe: snapshot POST is a read operation and emitted records are independently deduped.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "tokio::select macro expansion contains internal remainder arithmetic"
)]
async fn poll_loop(collection: &Collection, dedupe: &mut Window) {
    loop {
        tokio::select! {
            () = collection.cancellation.cancelled() => return,
            result = snapshot(collection) => {
                if let Ok(value) = result {
                    emit(collection, dedupe, &value);
                }
            }
        }
        time::sleep(collection.poll_interval).await;
    }
}

/// Maintains a dedicated stream, restarting it after process/session loss.
// cancel-safe: the handle is stopped on every branch after a successful start.
async fn stream_loop(collection: &Collection, dedupe: &mut Window) {
    let mut failures = 0_u8;
    loop {
        let started = collection
            .client
            .start(
                collection.path.clone(),
                &json!({"once":false,"max-lines":MAX_LINES}),
            )
            .await;
        let handle = if let Ok(handle) = started {
            failures = 0;
            handle
        } else {
            failures = failures.saturating_add(1);
            if failures >= STREAM_FAILURES_BEFORE_FALLBACK {
                poll_loop(collection, dedupe).await;
                return;
            }
            time::sleep(collection.stream_interval).await;
            continue;
        };
        let restart = consume_stream(collection, dedupe, &handle).await;
        if let Err(error) = handle.stop().await {
            tracing::debug!(%error, router = %collection.router, "router log stream cleanup failed");
        }
        if !restart {
            return;
        }
        time::sleep(collection.stream_interval).await;
    }
}

/// Reads one stream until cancellation or a request failure.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "tokio::select macro expansion contains internal remainder arithmetic"
)]
async fn consume_stream(
    collection: &Collection,
    dedupe: &mut Window,
    handle: &BackgroundHandle,
) -> bool {
    loop {
        let response = tokio::select! {
            () = collection.cancellation.cancelled() => return false,
            result = handle.next() => result,
        };
        match response {
            Ok(RciBody::Json(body)) => emit(collection, dedupe, &body.value),
            _ => return true,
        }
        time::sleep(collection.stream_interval).await;
    }
}

/// Reads one bounded log snapshot.
///
/// # Errors
///
/// Returns [`LogError`] for request or response-shape failures.
async fn snapshot(collection: &Collection) -> Result<Value, LogError> {
    match collection
        .client
        .post(
            &collection.path,
            &json!({"once":true,"max-lines":MAX_LINES}),
        )
        .await?
    {
        RciBody::Json(body) => Ok(body.value),
        RciBody::Text(_) | _ => Err(LogError::Response),
    }
}

/// Parses, deduplicates, and broadcasts one response.
fn emit(collection: &Collection, dedupe: &mut Window, value: &Value) {
    let utc: DateTime<Utc> = SystemTime::now().into();
    let Some(offset) = FixedOffset::east_opt(0) else {
        return;
    };
    let now = utc.with_timezone(&offset);
    let Ok(records) = parser::parse_records(&collection.router, value, now) else {
        return;
    };
    for mut record in records {
        if dedupe.accept(record.id) {
            if collection.redact_macs {
                record.message = redact::macs(&record.message);
            }
            remember(&collection.recent, &record);
            drop(collection.records.send(record));
        }
    }
}
