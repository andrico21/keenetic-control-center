//! Per-scrape metric vectors for the router families, refilled from the cache.

use alloc::collections::BTreeMap;

use prometheus::{
    CounterVec, GaugeVec, Opts,
    core::{Collector as _, Desc},
    proto::MetricFamily,
};

use super::{
    catalogue::{FAMILIES, MetricKind, Presence},
    failure::MetricsError,
};

/// One vector of the sink.
enum Vector {
    /// A gauge family.
    Gauge(GaugeVec),
    /// A counter family, refilled with the router-reported total.
    Counter(CounterVec),
}

/// The router families of [`FAMILIES`] as reusable vectors.
pub(super) struct Sink {
    /// Vectors by family name.
    vectors: BTreeMap<&'static str, Vector>,
}

impl Sink {
    /// Builds one vector per router family (self-metrics excluded).
    ///
    /// # Errors
    ///
    /// [`MetricsError::Prometheus`] for an invalid name or label.
    pub(super) fn new() -> Result<Self, MetricsError> {
        let mut vectors = BTreeMap::new();
        for family in FAMILIES
            .iter()
            .filter(|family| family.presence != Presence::SelfMetric)
        {
            let opts = Opts::new(family.name, family.help);
            let vector = match family.kind {
                MetricKind::Gauge => Vector::Gauge(GaugeVec::new(opts, family.labels)?),
                MetricKind::Counter => Vector::Counter(CounterVec::new(opts, family.labels)?),
                MetricKind::Histogram => return Err(MetricsError::Catalogue(family.name)),
            };
            drop(vectors.insert(family.name, vector));
        }
        Ok(Self { vectors })
    }

    /// Removes every series.
    pub(super) fn reset(&self) {
        for vector in self.vectors.values() {
            match vector {
                Vector::Gauge(gauge) => gauge.reset(),
                Vector::Counter(counter) => counter.reset(),
            }
        }
    }

    /// Sets one series; label values follow the catalogue order. Unknown names, label
    /// mismatches, non-finite values and negative counters are skipped.
    pub(super) fn put(&self, name: &str, labels: &[&str], value: f64) {
        if !value.is_finite() {
            return;
        }
        match self.vectors.get(name) {
            Some(Vector::Gauge(gauge)) => {
                if let Ok(series) = gauge.get_metric_with_label_values(labels) {
                    series.set(value);
                }
            }
            Some(Vector::Counter(counter)) => {
                if value >= 0.0_f64
                    && let Ok(series) = counter.get_metric_with_label_values(labels)
                {
                    series.inc_by(value);
                }
            }
            None => {}
        }
    }

    /// Descriptors of every vector.
    pub(super) fn descs(&self) -> Vec<&Desc> {
        self.vectors
            .values()
            .flat_map(|vector| match vector {
                Vector::Gauge(gauge) => gauge.desc(),
                Vector::Counter(counter) => counter.desc(),
            })
            .collect()
    }

    /// The current series of every vector.
    pub(super) fn collect(&self) -> Vec<MetricFamily> {
        self.vectors
            .values()
            .flat_map(|vector| match vector {
                Vector::Gauge(gauge) => gauge.collect(),
                Vector::Counter(counter) => counter.collect(),
            })
            .collect()
    }
}
