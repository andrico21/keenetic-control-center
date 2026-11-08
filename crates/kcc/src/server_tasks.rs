//! Background tasks `kcc serve` owns beside the listener: the firmware-update refresh and
//! the Web session gauge.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::poller::LIGHT_INTERVAL;
use kcc_telemetry::metrics::{instrumentation::SelfMetrics, web_sessions};
use kcc_web::{WebState, fleet_updates::ComponentsUpdateCheck};
use tokio::{task::JoinHandle, time::interval};

/// Re-checks due routers for newer firmware every light polling interval. Each router is
/// asked at most once per update-check TTL, and offline or unpolled routers not at all.
#[must_use]
pub(crate) fn refresh_updates(check: Arc<ComponentsUpdateCheck>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticks = interval(LIGHT_INTERVAL);
        loop {
            let _instant = ticks.tick().await;
            check.refresh().await;
        }
    })
}

/// Samples the signed-in Web sessions into `kcc_web_sessions`.
#[must_use]
pub(crate) fn track_sessions(web: WebState, metrics: Arc<SelfMetrics>) -> JoinHandle<()> {
    web_sessions::track(metrics, move || {
        let sessions = web.clone();
        async move { sessions.active_sessions().await }
    })
}
