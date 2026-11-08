//! Keeps the exported routers equal to the registry's profiles while kcc runs.
//!
//! Routers added or removed in the Web UI, through the CLI followed by SIGHUP, or by a
//! SIGHUP reload of `kcc.toml` start or stop being exported at once: the follower wakes on
//! the registry's change notification, never on a timer, and sends no router request.

use alloc::{collections::BTreeSet, sync::Arc};

use kcc_app::registry::RouterRegistry;
use tokio::task::JoinHandle;

use super::service::MetricsExporter;

/// Watches every registered router now and follows later registry changes, until the
/// registry is dropped or the returned task is aborted.
#[inline]
#[must_use]
pub fn follow_registry(
    exporter: Arc<MetricsExporter>,
    registry: Arc<RouterRegistry>,
) -> JoinHandle<()> {
    let mut changes = registry.subscribe_changes();
    tokio::spawn(async move {
        loop {
            reconcile(&exporter, &registry).await;
            if changes.changed().await.is_err() {
                return;
            }
        }
    })
}

/// Watches the registered routers the exporter lacks and unwatches the removed ones.
// cancel-safe: each step is one watch or unwatch; a cancelled pass is redone on the next
// change.
async fn reconcile(exporter: &MetricsExporter, registry: &RouterRegistry) {
    let wanted: BTreeSet<String> = match registry.list() {
        Ok(entries) => entries.into_iter().map(|entry| entry.profile.id).collect(),
        Err(error) => {
            tracing::warn!(%error, "metrics exporter could not list routers");
            return;
        }
    };
    let watched: BTreeSet<String> = exporter.watched().into_iter().collect();
    for router in wanted.difference(&watched) {
        exporter.watch(router).await;
    }
    for router in watched.difference(&wanted) {
        exporter.unwatch(router).await;
    }
}
