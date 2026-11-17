//! Bounded queues and lifecycle for configured log sink workers.

use alloc::sync::Arc;
use core::{fmt, mem, num::NonZeroUsize, time::Duration};
use std::sync::{Mutex, MutexGuard};

use kcc_app::settings::{LogSinkConfig, LogsConfig};
use tokio::{sync::Notify, task::JoinHandle, time::timeout};
use tokio_util::sync::CancellationToken;

use super::{
    destination::Sink,
    pipeline_delivery::{Stop, Worker, worker},
    queue::Pending,
    retry::{Clock, TokioClock},
    sink::DeliveryError,
    types::LogRecord,
};
use crate::metrics::{failure::MetricsError, instrumentation::SelfMetrics};

/// Maximum aggregate sink shutdown time.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);

/// Log forwarder construction failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ForwarderError {
    /// Sink credentials, TLS, or HTTP client construction failed.
    #[error(transparent)]
    Delivery(#[from] DeliveryError),
    /// The validated queue capacity could not be represented.
    #[error("log queue capacity is zero")]
    Capacity,
    /// Self-metric construction failed.
    #[error(transparent)]
    Metrics(#[from] MetricsError),
}

/// A bounded fan-out pipeline with one independent worker per configured sink.
pub struct LogForwarder {
    /// Producer handles.
    senders: Vec<Sender>,
    /// Worker tasks.
    tasks: Vec<JoinHandle<()>>,
    /// Cooperative cancellation: flush what is queued, then stop.
    cancellation: CancellationToken,
    /// Fired when the flush deadline passes: count what is left and stop.
    abort: CancellationToken,
}

impl fmt::Debug for LogForwarder {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogForwarder")
            .field("sinks", &self.senders.len())
            .finish_non_exhaustive()
    }
}

impl LogForwarder {
    /// Loads configured sinks and starts their bounded workers.
    ///
    /// # Errors
    ///
    /// Returns [`ForwarderError`] when a sink or queue cannot be constructed.
    #[inline]
    // NOT cancel-safe: cancelled while loading a later sink, the workers already spawned
    // for earlier sinks keep running detached because their cancellation token never fires.
    pub async fn start(
        config: &LogsConfig,
        metrics: Arc<SelfMetrics>,
    ) -> Result<Self, ForwarderError> {
        Self::start_with_clock(config, metrics, Arc::new(TokioClock)).await
    }

    /// Adds one record to every sink queue without waiting for destination I/O.
    #[inline]
    pub fn push(&self, record: &LogRecord) {
        for sender in &self.senders {
            sender.push(record.clone());
        }
    }

    /// Flushes pending records for at most ten seconds and stops every worker. Records still
    /// undelivered at the deadline, in flight or queued, are counted as dropped at shutdown.
    #[inline]
    // NOT cancel-safe: dropped while flushing, the workers are detached rather than stopped and
    // may flush past the ten-second deadline.
    pub async fn shutdown(mut self) {
        self.cancellation.cancel();
        for sender in &self.senders {
            sender.notify.notify_one();
        }
        let mut tasks = mem::take(&mut self.tasks);
        let completed = timeout(SHUTDOWN_DEADLINE, async {
            for task in &mut tasks {
                drop(task.await);
            }
        })
        .await
        .is_ok();
        if !completed {
            self.abort.cancel();
            for task in tasks.into_iter().filter(|task| !task.is_finished()) {
                drop(task.await);
            }
        }
    }

    /// Loads configured sinks and starts their bounded workers, which wait on `clock`
    /// between flushes and between delivery retries.
    ///
    /// # Errors
    ///
    /// Returns [`ForwarderError`] when a sink or queue cannot be constructed.
    #[inline]
    // NOT cancel-safe: cancelled while loading a later sink, the workers already spawned
    // for earlier sinks keep running detached because their cancellation token never fires.
    pub async fn start_with_clock(
        config: &LogsConfig,
        metrics: Arc<SelfMetrics>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ForwarderError> {
        let capacity = NonZeroUsize::new(config.queue_max).ok_or(ForwarderError::Capacity)?;
        let cancellation = CancellationToken::new();
        let abort = CancellationToken::new();
        let mut senders = Vec::new();
        let mut tasks = Vec::new();
        for (index, configured) in config.sinks.iter().enumerate() {
            let sink = Sink::load(configured).await?;
            let name = sink_name(configured, index);
            let sender = Sender::new(name.clone(), capacity, Arc::clone(&metrics));
            tasks.push(tokio::spawn(worker(Worker::new(
                name,
                sink,
                Arc::clone(&sender.queue),
                Arc::clone(&sender.notify),
                Arc::clone(&metrics),
                Arc::clone(&clock),
                Stop::new(cancellation.child_token(), abort.child_token()),
            ))));
            senders.push(sender);
        }
        Ok(Self {
            senders,
            tasks,
            cancellation,
            abort,
        })
    }
}

impl Drop for LogForwarder {
    #[inline]
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[derive(Debug)]
/// Producer handle for one sink.
struct Sender {
    /// Bounded queue.
    queue: Arc<Mutex<Pending>>,
    /// Worker notification.
    notify: Arc<Notify>,
}

impl Sender {
    /// Creates a producer handle.
    fn new(name: String, capacity: NonZeroUsize, metrics: Arc<SelfMetrics>) -> Self {
        Self {
            queue: Arc::new(Mutex::new(Pending::new(name, capacity, metrics))),
            notify: Arc::new(Notify::new()),
        }
    }
    /// Enqueues one record.
    fn push(&self, record: LogRecord) {
        lock(&self.queue).push(record);
        self.notify.notify_one();
    }
}

/// Builds one stable metric label.
fn sink_name(config: &LogSinkConfig, index: usize) -> String {
    let kind = match config {
        LogSinkConfig::Loki {
            url: _,
            tenant: _,
            basic_auth_user: _,
            password_file: _,
            bearer_token_file: _,
            ca_file: _,
            compress: _,
        } => "loki",
        LogSinkConfig::Elasticsearch {
            url: _,
            flavor: _,
            target: _,
            basic_auth_user: _,
            password_file: _,
            api_key_file: _,
            ca_file: _,
            compress: _,
        } => "search",
        LogSinkConfig::Stdout => "stdout",
        _ => "unknown",
    };
    format!("{kind}-{index}")
}

/// Recovers poisoned queue state.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
