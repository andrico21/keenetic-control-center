//! The exporter: watches routers through the shared poller and registers the collector.

use alloc::{collections::BTreeMap, sync::Arc};
use core::fmt;
use std::sync::Mutex;

use kcc_app::{
    poller::{MetricsCadence, PollResult, Poller},
    settings::MetricsConfig,
};
use prometheus::Registry;
use tokio::{sync::watch, task::JoinHandle, time::Instant};

use super::{
    clients::PerClient,
    collector::{Cached, Shared, SnapshotCollector, lock},
    failure::MetricsError,
    instrumentation::SelfMetrics,
    sink::Sink,
};

/// Renders router metrics from the shared poller's cache.
pub struct MetricsExporter {
    /// State shared with the collector and watchers.
    shared: Arc<Shared>,
    /// The shared poller.
    poller: Arc<Poller>,
    /// One cache-filling task per watched router.
    watchers: Mutex<BTreeMap<String, JoinHandle<()>>>,
}

impl fmt::Debug for MetricsExporter {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetricsExporter")
            .field("cadence", &self.shared.cadence)
            .field("per_client", &self.shared.per_client)
            .finish_non_exhaustive()
    }
}

impl MetricsExporter {
    /// Creates an exporter for `config` on top of `poller`.
    ///
    /// # Errors
    ///
    /// [`MetricsError`] when a family cannot be built.
    #[inline]
    pub fn new(
        poller: Arc<Poller>,
        config: &MetricsConfig,
        self_metrics: Arc<SelfMetrics>,
    ) -> Result<Self, MetricsError> {
        let shared = Shared {
            cadence: MetricsCadence::new(config.interval, config.heavy_interval),
            per_client: PerClient {
                enabled: config.per_client,
                max: usize::try_from(config.per_client_max).unwrap_or(usize::MAX),
                label: config.per_client_label,
            },
            routers: Mutex::new(BTreeMap::new()),
            sink: Sink::new()?,
            pseudonyms: Mutex::new(BTreeMap::new()),
            dropped: Mutex::new(BTreeMap::new()),
            scrape: Mutex::new(()),
            self_metrics,
        };
        Ok(Self {
            shared: Arc::new(shared),
            poller,
            watchers: Mutex::new(BTreeMap::new()),
        })
    }

    /// Registers the router collector and the self-metrics on `registry` (the kit's
    /// `McpMetrics::registry`).
    ///
    /// # Errors
    ///
    /// [`MetricsError::Prometheus`] on a name collision.
    #[inline]
    pub fn register(&self, registry: &Registry) -> Result<(), MetricsError> {
        registry.register(Box::new(SnapshotCollector(Arc::clone(&self.shared))))?;
        self.shared.self_metrics.register(registry)
    }

    /// Starts exporting `router`: registers the permanent metrics subscription with the
    /// shared poller and caches every successful snapshot it publishes.
    // cancel-safe: the subscription is registered before the watcher starts; a cancelled
    // call leaves at most a registered subscription without a cache entry.
    #[inline]
    pub async fn watch(&self, router: &str) {
        let receiver = self
            .poller
            .subscribe_metrics(router, self.shared.cadence)
            .await;
        drop(lock(&self.shared.routers).insert(
            router.to_owned(),
            Cached {
                snapshot: None,
                received: Instant::now(),
            },
        ));
        let task = tokio::spawn(follow(
            Arc::clone(&self.shared),
            router.to_owned(),
            receiver,
        ));
        let replaced = lock(&self.watchers).insert(router.to_owned(), task);
        if let Some(previous) = replaced {
            previous.abort();
        }
    }

    /// Stops exporting `router` and ends its metrics subscription.
    // cancel-safe: local map removals followed by one map removal in the poller.
    #[inline]
    pub async fn unwatch(&self, router: &str) {
        let removed = lock(&self.watchers).remove(router);
        if let Some(task) = removed {
            task.abort();
        }
        drop(lock(&self.shared.routers).remove(router));
        self.poller.unsubscribe_metrics(router).await;
    }
}

impl Drop for MetricsExporter {
    #[inline]
    fn drop(&mut self) {
        for task in lock(&self.watchers).values() {
            task.abort();
        }
    }
}

/// Copies every successful snapshot of `router` into the cache; counts failed rounds.
async fn follow(
    shared: Arc<Shared>,
    router: String,
    mut receiver: watch::Receiver<Option<PollResult>>,
) {
    loop {
        let published = receiver.borrow_and_update().clone();
        match published {
            Some(Ok(snapshot)) => {
                let first = lock(&shared.routers)
                    .get_mut(&router)
                    .is_some_and(|cached| {
                        let first = cached.snapshot.is_none();
                        cached.snapshot = Some(Arc::new(snapshot));
                        cached.received = Instant::now();
                        first
                    });
                if first {
                    tracing::info!(router = %router, "router metrics available");
                }
            }
            Some(Err(_)) => shared.self_metrics.poller_error(&router),
            None => {}
        }
        if receiver.changed().await.is_err() {
            return;
        }
    }
}
