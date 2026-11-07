//! Process-level ownership of collectors, subscribers, and sink forwarding.

use alloc::{collections::BTreeMap, sync::Arc};
use core::mem;

use kcc_app::settings::LogsConfig;
use kcc_rci::RciClient;
use thiserror::Error;
use tokio::{sync::broadcast, task::JoinHandle};

use super::{
    pipeline::{ForwarderError, LogForwarder},
    service::{LogCollector, LogError},
    types::LogRecord,
};
use crate::metrics::instrumentation::SelfMetrics;

/// Router-log runtime construction failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StartError {
    /// One configured sink could not be loaded.
    #[error(transparent)]
    Forwarder(#[from] ForwarderError),
    /// One selected collector could not be started.
    #[error(transparent)]
    Collector(#[from] LogError),
}

/// All log collectors and sink workers owned by one server process.
#[derive(Debug)]
#[non_exhaustive]
pub struct Service {
    /// One collector per selected router.
    collectors: BTreeMap<String, LogCollector>,
    /// Fan-out relay tasks.
    relays: Vec<JoinHandle<()>>,
    /// Shared sink pipeline.
    forwarder: Option<Arc<LogForwarder>>,
}

impl Service {
    /// Starts selected collectors and one forwarding pipeline.
    ///
    /// # Errors
    ///
    /// Returns [`StartError`] when a sink or selected collector cannot start.
    // NOT cancel-safe: cancellation after a collector starts leaves its task running until drop.
    #[inline]
    pub async fn start(
        routers: Vec<(String, Arc<RciClient>)>,
        config: &LogsConfig,
        metrics: Arc<SelfMetrics>,
    ) -> Result<Self, StartError> {
        let forwarder = Arc::new(LogForwarder::start(config, Arc::clone(&metrics)).await?);
        let mut collectors = BTreeMap::new();
        let mut relays = Vec::new();
        for (router, client) in routers {
            if !selected(config, &router) {
                continue;
            }
            let collector = LogCollector::start(&router, client, config)?;
            let mut receiver = collector.subscribe();
            let relay_forwarder = Arc::clone(&forwarder);
            let relay_metrics = Arc::clone(&metrics);
            let relay_router = router.clone();
            relays.push(tokio::spawn(async move {
                loop {
                    match receiver.recv().await {
                        Ok(record) => {
                            relay_metrics.log_record_received(&relay_router);
                            relay_forwarder.push(&record);
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            relay_metrics.log_records_dropped("collector", "lagged", skipped);
                        }
                        Err(broadcast::error::RecvError::Closed) => return,
                    }
                }
            }));
            drop(collectors.insert(router, collector));
        }
        Ok(Self {
            collectors,
            relays,
            forwarder: Some(forwarder),
        })
    }

    /// Subscribes a reader to the collector already owned for `router`.
    #[inline]
    #[must_use]
    pub fn subscribe(&self, router: &str) -> Option<broadcast::Receiver<LogRecord>> {
        self.collectors.get(router).map(LogCollector::subscribe)
    }

    /// Stops router streams, relays, and sink workers.
    // NOT cancel-safe: cancellation can lose task results after shutdown has started.
    #[inline]
    pub async fn shutdown(mut self) {
        for (_, collector) in mem::take(&mut self.collectors) {
            drop(collector.shutdown().await);
        }
        for relay in self.relays.drain(..) {
            drop(relay.await);
        }
        if let Some(shared) = self.forwarder.take()
            && let Ok(forwarder) = Arc::try_unwrap(shared)
        {
            forwarder.shutdown().await;
        }
    }
}

impl Drop for Service {
    #[inline]
    fn drop(&mut self) {
        for relay in &self.relays {
            relay.abort();
        }
    }
}

/// Returns whether one router is selected by the validated configuration.
fn selected(config: &LogsConfig, router: &str) -> bool {
    config.routers.is_empty() || config.routers.iter().any(|selected| selected == router)
}
