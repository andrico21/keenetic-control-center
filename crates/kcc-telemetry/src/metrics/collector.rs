//! The scrape-time collector: renders the poller cache, never calls a router.

use alloc::{collections::BTreeMap, sync::Arc};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kcc_app::poller::{MetricsCadence, Snapshot};
use prometheus::{
    core::{Collector, Desc},
    proto::MetricFamily,
};
use tokio::time::Instant;

use super::{
    clients::{self, PerClient},
    instrumentation::SelfMetrics,
    interfaces,
    json::count,
    sink::Sink,
    system,
};

/// Data older than this many polling intervals is omitted.
const STALE_INTERVALS: u32 = 3;

/// The latest successful snapshot of one watched router.
#[derive(Debug)]
pub(super) struct Cached {
    /// Latest snapshot; `None` before the first successful round.
    pub snapshot: Option<Arc<Snapshot>>,
    /// When `snapshot` was received.
    pub received: Instant,
}

/// State shared by the scrape collector and the per-router watchers.
pub(super) struct Shared {
    /// Metrics cadence (staleness is 3x of it).
    pub cadence: MetricsCadence,
    /// Per-client settings.
    pub per_client: PerClient,
    /// Cache per watched router.
    pub routers: Mutex<BTreeMap<String, Cached>>,
    /// Router families.
    pub sink: Sink,
    /// Serializes scrapes (the sink is refilled per scrape).
    pub scrape: Mutex<()>,
    /// Self-metrics fed by the watchers.
    pub self_metrics: Arc<SelfMetrics>,
}

/// Locks `mutex`, recovering the data of a poisoned lock (every writer leaves it whole).
pub(super) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shared {
    /// Renders one router into the sink; returns the per-client series dropped.
    fn render(&self, router: &str, cached: &Cached, now: Instant) -> u64 {
        let age = now.saturating_duration_since(cached.received);
        let fresh = cached
            .snapshot
            .as_ref()
            .filter(|_| age <= self.cadence.light.saturating_mul(STALE_INTERVALS));
        let Some(snapshot) = fresh else {
            self.sink.put("keenetic_up", &[router], 0.0);
            return 0;
        };
        self.sink.put("keenetic_up", &[router], 1.0);
        system::light(&self.sink, router, snapshot);
        interfaces::light(&self.sink, router, snapshot);
        if snapshot.heavy_age.saturating_add(age)
            > self.cadence.heavy.saturating_mul(STALE_INTERVALS)
        {
            return 0;
        }
        system::info(&self.sink, router, &snapshot.info);
        clients::heavy(&self.sink, router, snapshot, self.per_client)
    }
}

/// The [`Collector`] registered on the kit registry.
pub(super) struct SnapshotCollector(pub Arc<Shared>);

impl Collector for SnapshotCollector {
    fn desc(&self) -> Vec<&Desc> {
        self.0.sink.descs()
    }

    fn collect(&self) -> Vec<MetricFamily> {
        let shared = &self.0;
        let _scrape = lock(&shared.scrape);
        shared.sink.reset();
        let now = Instant::now();
        let routers = lock(&shared.routers);
        for (router, cached) in routers.iter() {
            let newly = shared.render(router, cached, now);
            if shared.per_client.enabled {
                shared
                    .sink
                    .put("kcc_metrics_series_dropped", &[router], count(newly));
            }
        }
        drop(routers);
        shared.sink.collect()
    }
}
