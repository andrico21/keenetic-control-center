//! The `/metrics` listener of `kcc serve`, fed from the shared poller's cache.
#![expect(
    clippy::missing_errors_doc,
    reason = "binary assembly: the startup error is reported by `kcc serve`, not an API caller"
)]

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::settings::Config;
use kcc_telemetry::metrics::{registry_follow::follow_registry, service::MetricsExporter};
use rmcp_server_kit::{metrics::McpMetrics, transport::McpServerConfig};

use crate::{server_error::ServerError, server_services::Services};

/// Serves `/metrics` from the shared poller's cache when `[metrics] enabled`.
///
/// The kit listener is plaintext and unauthenticated by design; `Config::validate`
/// already refused ports below 1024 and a non-loopback bind without
/// `allow_non_loopback`.
// cancel-safe: synchronous; the registry follower registers the poller subscriptions.
pub(crate) fn with_metrics(
    services: &Services,
    server: McpServerConfig,
    config: &Config,
) -> Result<(McpServerConfig, Option<Arc<MetricsExporter>>), ServerError> {
    if !config.metrics.enabled {
        return Ok((server, None));
    }
    let Some(self_metrics) = services.metrics.clone() else {
        return Ok((server, None));
    };
    if !config.metrics.bind.ip().is_loopback() {
        tracing::warn!(bind = %config.metrics.bind, "unauthenticated metrics listener bound beyond loopback");
    }
    let kit = Arc::new(McpMetrics::new()?);
    let exporter = Arc::new(MetricsExporter::new(
        Arc::clone(&services.poller),
        &config.metrics,
        Arc::clone(&self_metrics),
    )?);
    exporter.register(&kit.registry)?;
    drop(follow_registry(
        Arc::clone(&exporter),
        Arc::clone(&services.registry),
    ));
    drop(self_metrics.track_jobs(Arc::clone(&services.jobs)));
    Ok((
        server
            .with_metrics(config.metrics.bind.to_string())
            .with_metrics_handle(kit),
        Some(exporter),
    ))
}
