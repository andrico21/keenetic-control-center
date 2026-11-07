//! kcc self-metrics: build, RCI requests and logins, poller errors, jobs, Web sessions.

use alloc::{collections::BTreeMap, sync::Arc};
use core::time::Duration;

use kcc_app::{jobs::JobRunner, registry::RciObserverFactory};
use kcc_rci::observe::{LoginScheme, RciObserver, RequestOutcome};
use prometheus::{
    HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};
use tokio::{sync::broadcast::error::RecvError, task::JoinHandle};

use super::{catalogue::find, failure::MetricsError};

/// RCI request-duration buckets (seconds): LAN round trips up to slow background reads.
const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// Process-wide kcc counters and gauges.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SelfMetrics {
    /// `kcc_build_info{version}`.
    build_info: IntGaugeVec,
    /// `kcc_router_requests_total{router,outcome}`.
    requests: IntCounterVec,
    /// `kcc_router_request_duration_seconds{router}`.
    durations: HistogramVec,
    /// `kcc_router_auth_total{router,scheme,outcome}`.
    logins: IntCounterVec,
    /// `kcc_poller_errors_total{router}`.
    poller_errors: IntCounterVec,
    /// `kcc_jobs{kind,state}`.
    jobs: IntGaugeVec,
    /// `kcc_web_sessions`.
    web_sessions: IntGauge,
    /// `kcc_log_records_dropped_total{sink,reason}` (log pipeline).
    log_dropped: IntCounterVec,
    /// `kcc_log_records_received_total{router}`.
    log_received: IntCounterVec,
    /// `kcc_log_records_forwarded_total{sink}`.
    log_forwarded: IntCounterVec,
    /// `kcc_log_retries_total{sink}`.
    log_retries: IntCounterVec,
}

/// Catalogue options for `name`.
///
/// # Errors
///
/// [`MetricsError::Catalogue`] when `name` is not catalogued.
fn opts(name: &'static str) -> Result<(Opts, &'static [&'static str]), MetricsError> {
    let family = find(name).ok_or(MetricsError::Catalogue(name))?;
    Ok((Opts::new(family.name, family.help), family.labels))
}

impl SelfMetrics {
    /// Creates the self-metrics with `kcc_build_info{version}` set to 1.
    ///
    /// # Errors
    ///
    /// [`MetricsError`] when a catalogue entry is missing or invalid.
    #[inline]
    pub fn new(version: &str) -> Result<Arc<Self>, MetricsError> {
        let (build, build_labels) = opts("kcc_build_info")?;
        let (requests, request_labels) = opts("kcc_router_requests_total")?;
        let (durations, duration_labels) = opts("kcc_router_request_duration_seconds")?;
        let (logins, login_labels) = opts("kcc_router_auth_total")?;
        let (errors, error_labels) = opts("kcc_poller_errors_total")?;
        let (jobs, job_labels) = opts("kcc_jobs")?;
        let (sessions, _) = opts("kcc_web_sessions")?;
        let (log_dropped, log_labels) = opts("kcc_log_records_dropped_total")?;
        let (log_received, received_labels) = opts("kcc_log_records_received_total")?;
        let (log_forwarded, forwarded_labels) = opts("kcc_log_records_forwarded_total")?;
        let (log_retries, retry_labels) = opts("kcc_log_retries_total")?;
        let metrics = Self {
            build_info: IntGaugeVec::new(build, build_labels)?,
            requests: IntCounterVec::new(requests, request_labels)?,
            durations: HistogramVec::new(
                HistogramOpts::from(durations).buckets(DURATION_BUCKETS.to_vec()),
                duration_labels,
            )?,
            logins: IntCounterVec::new(logins, login_labels)?,
            poller_errors: IntCounterVec::new(errors, error_labels)?,
            jobs: IntGaugeVec::new(jobs, job_labels)?,
            web_sessions: IntGauge::with_opts(sessions)?,
            log_dropped: IntCounterVec::new(log_dropped, log_labels)?,
            log_received: IntCounterVec::new(log_received, received_labels)?,
            log_forwarded: IntCounterVec::new(log_forwarded, forwarded_labels)?,
            log_retries: IntCounterVec::new(log_retries, retry_labels)?,
        };
        metrics
            .build_info
            .get_metric_with_label_values(&[version])?
            .set(1);
        Ok(Arc::new(metrics))
    }

    /// Registers every self-metric on `registry`.
    ///
    /// # Errors
    ///
    /// [`MetricsError::Prometheus`] on a name collision.
    #[inline]
    pub fn register(&self, registry: &Registry) -> Result<(), MetricsError> {
        registry.register(Box::new(self.build_info.clone()))?;
        registry.register(Box::new(self.requests.clone()))?;
        registry.register(Box::new(self.durations.clone()))?;
        registry.register(Box::new(self.logins.clone()))?;
        registry.register(Box::new(self.poller_errors.clone()))?;
        registry.register(Box::new(self.jobs.clone()))?;
        registry.register(Box::new(self.web_sessions.clone()))?;
        registry.register(Box::new(self.log_dropped.clone()))?;
        registry.register(Box::new(self.log_received.clone()))?;
        registry.register(Box::new(self.log_forwarded.clone()))?;
        registry.register(Box::new(self.log_retries.clone()))?;
        Ok(())
    }

    /// A factory for [`kcc_app::registry::RouterRegistry::with_rci_observers`].
    #[inline]
    #[must_use]
    pub fn rci_observers(self: &Arc<Self>) -> RciObserverFactory {
        let metrics = Arc::clone(self);
        Arc::new(move |router: &str| {
            let observer: Arc<dyn RciObserver> = Arc::new(RouterObserver {
                router: router.to_owned(),
                metrics: Arc::clone(&metrics),
            });
            observer
        })
    }

    /// Sets `kcc_web_sessions`.
    #[inline]
    pub fn set_web_sessions(&self, sessions: i64) {
        self.web_sessions.set(sessions);
    }

    /// Counts `records` log records that `sink` dropped for `reason`.
    #[inline]
    pub fn log_records_dropped(&self, sink: &str, reason: &str, records: u64) {
        if let Ok(counter) = self
            .log_dropped
            .get_metric_with_label_values(&[sink, reason])
        {
            counter.inc_by(records);
        }
    }

    /// Counts one accepted router log record.
    #[inline]
    pub fn log_record_received(&self, router: &str) {
        if let Ok(counter) = self.log_received.get_metric_with_label_values(&[router]) {
            counter.inc();
        }
    }

    /// Counts records accepted by one sink.
    #[inline]
    pub fn log_records_forwarded(&self, sink: &str, records: u64) {
        if let Ok(counter) = self.log_forwarded.get_metric_with_label_values(&[sink]) {
            counter.inc_by(records);
        }
    }

    /// Counts one delivery retry for a sink.
    #[inline]
    pub fn log_retry(&self, sink: &str) {
        if let Ok(counter) = self.log_retries.get_metric_with_label_values(&[sink]) {
            counter.inc();
        }
    }

    /// Counts one failed polling round of `router`.
    pub(super) fn poller_error(&self, router: &str) {
        if let Ok(counter) = self.poller_errors.get_metric_with_label_values(&[router]) {
            counter.inc();
        }
    }

    /// Follows the job events of `jobs` into `kcc_jobs` until the runner is dropped.
    ///
    /// Running jobs are a live gauge; finished states count jobs finished since the
    /// tracker started.
    #[inline]
    #[must_use]
    pub fn track_jobs(self: &Arc<Self>, jobs: Arc<JobRunner>) -> JoinHandle<()> {
        let metrics = Arc::clone(self);
        let mut events = jobs.subscribe();
        tokio::spawn(async move {
            let mut known: BTreeMap<String, (String, String)> = BTreeMap::new();
            loop {
                let event = match events.recv().await {
                    Ok(event) => event,
                    Err(RecvError::Lagged(_)) => continue,
                    Err(RecvError::Closed) => return,
                };
                let Ok(record) = jobs.get(&event.id) else {
                    continue;
                };
                let Some(state) = serde_json::to_value(event.status)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                else {
                    continue;
                };
                metrics.job_transition(&mut known, (event.id, record.kind), state);
            }
        })
    }

    /// Applies one job state change to `kcc_jobs`.
    fn job_transition(
        &self,
        known: &mut BTreeMap<String, (String, String)>,
        (id, kind): (String, String),
        state: String,
    ) {
        if known
            .get(&id)
            .is_some_and(|(_, previous)| *previous == state)
        {
            return;
        }
        if let Some((previous_kind, previous)) = known.remove(&id)
            && let Ok(gauge) = self
                .jobs
                .get_metric_with_label_values(&[&previous_kind, &previous])
        {
            gauge.dec();
        }
        if let Ok(gauge) = self.jobs.get_metric_with_label_values(&[&kind, &state]) {
            gauge.inc();
        }
        if state == "running" {
            drop(known.insert(id, (kind, state)));
        }
    }
}

/// The [`RciObserver`] of one router.
#[derive(Debug)]
struct RouterObserver {
    /// Router profile id.
    router: String,
    /// Shared counters.
    metrics: Arc<SelfMetrics>,
}

impl RciObserver for RouterObserver {
    fn request(&self, outcome: RequestOutcome, elapsed: Duration) {
        let router = self.router.as_str();
        if let Ok(counter) = self
            .metrics
            .requests
            .get_metric_with_label_values(&[router, outcome.as_str()])
        {
            counter.inc();
        }
        if let Ok(histogram) = self
            .metrics
            .durations
            .get_metric_with_label_values(&[router])
        {
            histogram.observe(elapsed.as_secs_f64());
        }
    }

    fn authentication(&self, scheme: Option<LoginScheme>, success: bool) {
        let scheme_label = scheme.map_or("unknown", LoginScheme::as_str);
        let outcome = if success { "success" } else { "failure" };
        if let Ok(counter) = self.metrics.logins.get_metric_with_label_values(&[
            self.router.as_str(),
            scheme_label,
            outcome,
        ]) {
            counter.inc();
        }
    }
}
