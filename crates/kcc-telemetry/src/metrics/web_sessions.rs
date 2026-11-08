//! `kcc_web_sessions`, sampled from the Web UI's session store.

use alloc::sync::Arc;
use core::time::Duration;

use tokio::{task::JoinHandle, time::interval};

use super::instrumentation::SelfMetrics;

/// How often the number of signed-in Web sessions is sampled; the light polling cadence.
pub const WEB_SESSIONS_INTERVAL: Duration = Duration::from_secs(15);

/// Sets `kcc_web_sessions` from `count` at once and then every [`WEB_SESSIONS_INTERVAL`],
/// until the returned task is aborted.
#[inline]
#[must_use]
pub fn track<F, Fut>(metrics: Arc<SelfMetrics>, count: F) -> JoinHandle<()>
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = usize> + Send,
{
    tokio::spawn(async move {
        let mut ticks = interval(WEB_SESSIONS_INTERVAL);
        loop {
            let _instant = ticks.tick().await;
            metrics.set_web_sessions(i64::try_from(count().await).unwrap_or(i64::MAX));
        }
    })
}
