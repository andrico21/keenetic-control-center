//! The `/metrics` listener of `kcc serve`, fed from the shared poller's cache.
//!
//! The exporter, its registry follower and the job tracker start once per process; each
//! main listener generation serves them on a fresh kit registry, so the kit's own
//! `rmcp_server_kit_*` counters restart from zero when the main listener restarts while the
//! `kcc_*` series continue.
#![expect(
    clippy::missing_errors_doc,
    reason = "binary assembly: the startup error is reported by `kcc serve`, not an API caller"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::net::SocketAddr;

use kcc_app::settings::Config;
use kcc_telemetry::metrics::{
    failure::MetricsError, registry_follow::follow_registry, service::MetricsExporter,
};
use rmcp_server_kit::{RmcpServerKitError, metrics::McpMetrics, transport::McpServerConfig};

use crate::{server_error::ServerError, server_services::Services};

/// The process's metrics exporter and the address its `/metrics` listener binds.
#[derive(Clone)]
pub(crate) struct Metrics {
    /// Exports the poller's cache and the self-metrics; created once.
    exporter: Arc<MetricsExporter>,
    /// `[metrics] bind`.
    bind: SocketAddr,
}

/// Why a main generation's metrics could not be set up.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AttachError {
    /// The kit's registry could not be built.
    #[error("{0}")]
    Kit(#[from] RmcpServerKitError),
    /// The exporter could not be registered in it.
    #[error("{0}")]
    Exporter(#[from] MetricsError),
}

impl Metrics {
    /// `exporter` served at `bind`.
    pub(crate) const fn new(exporter: Arc<MetricsExporter>, bind: SocketAddr) -> Self {
        Self { exporter, bind }
    }

    /// The `/metrics` listener's address.
    pub(crate) const fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// `server` serving `/metrics` from a fresh kit registry holding the exporter.
    // cancel-safe: synchronous.
    pub(crate) fn attach(&self, server: McpServerConfig) -> Result<McpServerConfig, AttachError> {
        let kit = Arc::new(McpMetrics::new()?);
        self.exporter.register(&kit.registry)?;
        Ok(server
            .with_metrics(self.bind.to_string())
            .with_metrics_handle(kit))
    }
}

/// Starts the exporter when `[metrics] enabled`: the registry follower and the job tracker
/// run from here on, once per process.
///
/// The kit listener is plaintext and unauthenticated by design; `Config::validate`
/// already refused ports below 1024 and a non-loopback bind without
/// `allow_non_loopback`.
// cancel-safe: synchronous; the registry follower registers the poller subscriptions.
pub(crate) fn start(services: &Services, config: &Config) -> Result<Option<Metrics>, ServerError> {
    if !config.metrics.enabled {
        return Ok(None);
    }
    let Some(self_metrics) = services.metrics.clone() else {
        return Ok(None);
    };
    if !config.metrics.bind.ip().is_loopback() {
        tracing::warn!(bind = %config.metrics.bind, "unauthenticated metrics listener bound beyond loopback");
    }
    let exporter = Arc::new(MetricsExporter::new(
        Arc::clone(&services.poller),
        &config.metrics,
        Arc::clone(&self_metrics),
    )?);
    drop(follow_registry(
        Arc::clone(&exporter),
        Arc::clone(&services.registry),
    ));
    drop(self_metrics.track_jobs(Arc::clone(&services.jobs)));
    Ok(Some(Metrics::new(exporter, config.metrics.bind)))
}
