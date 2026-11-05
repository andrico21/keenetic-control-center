//! Subscriber-driven shared router polling.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    clippy::shadow_reuse,
    clippy::significant_drop_tightening,
    clippy::renamed_function_params,
    reason = "poll-loop helpers and async public methods are lifecycle code rather than inline candidates"
)]

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{fmt, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use kcc_rci::{RciBody, RciClient, RciPath, capabilities::RouterInfo};
use serde_json::{Value, json};
use tokio::{
    sync::{Mutex, watch},
    time::{Instant, sleep},
};

use crate::registry::{RegistryError, RouterRegistry};

/// Normal light-resource polling period.
pub const LIGHT_INTERVAL: Duration = Duration::from_secs(15);
/// Normal heavy-resource polling period.
pub const HEAVY_INTERVAL: Duration = Duration::from_secs(60);
/// Error backoff period.
pub const ERROR_BACKOFF: Duration = Duration::from_secs(120);
/// Delay before an idle router task exits.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Shared state snapshot for one router.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Snapshot {
    /// Detected identity and capabilities.
    pub info: RouterInfo,
    /// `show system` response.
    pub system: Value,
    /// `show internet` response.
    pub internet: Value,
    /// Full interface response, refreshed on the heavy cadence.
    pub interfaces_summary: Value,
    /// Number of hotspot clients, refreshed on the heavy cadence.
    pub clients_count: u64,
    /// Wi-Fi summary.
    pub wifi_summary: Value,
    /// `show last-change` response.
    pub last_change: Value,
    /// Unix timestamp in seconds when this snapshot completed.
    pub fetched_at: u64,
}

/// Poller failures surfaced to subscribers.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PollError {
    /// Registry or connection failure.
    #[error("router registry failure: {reason}")]
    Registry {
        /// Redacted failure text.
        reason: String,
    },
    /// A read request failed.
    #[error("router polling request failed")]
    Request,
}

impl From<RegistryError> for PollError {
    fn from(error: RegistryError) -> Self {
        Self::Registry {
            reason: error.to_string(),
        }
    }
}

/// Latest snapshot result published through a watch channel.
pub type PollResult = Result<Snapshot, PollError>;

/// Configurable poll timing, exposed to deterministic tests.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct PollIntervals {
    /// Light cadence.
    pub light: Duration,
    /// Heavy cadence.
    pub heavy: Duration,
    /// Error cadence.
    pub error: Duration,
    /// Idle shutdown delay.
    pub idle: Duration,
}

impl Default for PollIntervals {
    fn default() -> Self {
        Self {
            light: LIGHT_INTERVAL,
            heavy: HEAVY_INTERVAL,
            error: ERROR_BACKOFF,
            idle: IDLE_TIMEOUT,
        }
    }
}

impl PollIntervals {
    /// Creates explicit light, heavy, error, and idle timings.
    #[inline]
    #[must_use]
    pub const fn new(light: Duration, heavy: Duration, error: Duration, idle: Duration) -> Self {
        Self {
            light,
            heavy,
            error,
            idle,
        }
    }
}

/// One shared polling task and watch stream per router.
pub struct Poller {
    /// Router registry and client pool.
    registry: Arc<RouterRegistry>,
    /// Active router channels.
    channels: Mutex<BTreeMap<String, watch::Sender<Option<PollResult>>>>,
    /// Completed light polling rounds per router.
    light_rounds: Mutex<BTreeMap<String, u64>>,
    /// Poll timing.
    intervals: PollIntervals,
}

impl fmt::Debug for Poller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Poller")
            .field("registry", &self.registry)
            .field("intervals", &self.intervals)
            .finish_non_exhaustive()
    }
}

impl Poller {
    /// Creates a production-cadence poller.
    #[inline]
    #[must_use]
    pub fn new(registry: Arc<RouterRegistry>) -> Arc<Self> {
        Self::with_intervals(registry, PollIntervals::default())
    }

    /// Creates a poller with explicit timing.
    #[inline]
    #[must_use]
    pub fn with_intervals(registry: Arc<RouterRegistry>, intervals: PollIntervals) -> Arc<Self> {
        Arc::new(Self {
            registry,
            channels: Mutex::new(BTreeMap::new()),
            light_rounds: Mutex::new(BTreeMap::new()),
            intervals,
        })
    }

    /// Subscribes to one router, starting its sole polling task lazily.
    // cancel-safe: channel setup has no external side effect beyond starting a read-only task.
    pub async fn subscribe(self: &Arc<Self>, router: &str) -> watch::Receiver<Option<PollResult>> {
        let mut channels = self.channels.lock().await;
        if let Some(sender) = channels.get(router) {
            return sender.subscribe();
        }
        let (sender, receiver) = watch::channel(None);
        drop(channels.insert(router.to_owned(), sender));
        let owner = Arc::clone(self);
        let router_id = router.to_owned();
        drop(tokio::spawn(async move {
            owner.run(router_id).await;
        }));
        receiver
    }

    /// Returns completed light polling rounds for observability and cadence tests.
    pub async fn light_rounds(&self, router: &str) -> u64 {
        self.light_rounds
            .lock()
            .await
            .get(router)
            .copied()
            .unwrap_or(0)
    }

    /// Runs one router loop until it has stayed idle for the configured timeout.
    async fn run(self: Arc<Self>, router: String) {
        let mut heavy_snapshot: Option<(Value, u64, Instant)> = None;
        let mut idle_since = None;
        loop {
            let sender = {
                let channels = self.channels.lock().await;
                channels.get(&router).cloned()
            };
            let Some(sender) = sender else {
                return;
            };
            if sender.receiver_count() == 0 {
                let since = idle_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= self.intervals.idle {
                    drop(self.channels.lock().await.remove(&router));
                    return;
                }
                sleep(self.intervals.light.min(self.intervals.idle)).await;
                continue;
            }
            idle_since = None;
            let result = self.fetch(&router, &mut heavy_snapshot).await;
            if result.is_ok() {
                let mut rounds = self.light_rounds.lock().await;
                let count = rounds.entry(router.clone()).or_default();
                *count = count.saturating_add(1);
            }
            let delay = if result.is_ok() {
                self.intervals.light
            } else {
                self.intervals.error
            };
            drop(sender.send(Some(result)));
            sleep(delay).await;
        }
    }

    /// Fetches one snapshot, reusing heavy values until their cadence expires.
    async fn fetch(
        &self,
        router: &str,
        heavy_snapshot: &mut Option<(Value, u64, Instant)>,
    ) -> PollResult {
        let client = self.registry.poll_client(router).await?;
        let info = self.registry.poll_info(router).await?;
        let system = show_json(&client, &["show", "system"])
            .await
            .unwrap_or(Value::Null);
        let internet = show_json(&client, &["show", "internet"])
            .await
            .unwrap_or(Value::Null);
        let wifi_summary = show_json(&client, &["show", "interface", "bands"])
            .await
            .unwrap_or(Value::Null);
        let last_change = show_json(&client, &["show", "last-change"]).await?;
        let refresh_heavy = heavy_snapshot
            .as_ref()
            .is_none_or(|(_, _, fetched)| fetched.elapsed() >= self.intervals.heavy);
        if refresh_heavy {
            let interfaces = show_json(&client, &["show", "interface"])
                .await
                .unwrap_or(Value::Null);
            let hotspot = show_json(&client, &["show", "ip", "hotspot"])
                .await
                .unwrap_or_else(|_| json!({}));
            let count = count_clients(&hotspot);
            *heavy_snapshot = Some((interfaces, count, Instant::now()));
        }
        let (interfaces_summary, clients_count, _) =
            heavy_snapshot.as_ref().ok_or(PollError::Request)?;
        Ok(Snapshot {
            info,
            system,
            internet,
            interfaces_summary: interfaces_summary.clone(),
            clients_count: *clients_count,
            wifi_summary,
            last_change,
            fetched_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs()),
        })
    }
}

/// Reads one JSON show resource.
async fn show_json(client: &RciClient, segments: &[&str]) -> Result<Value, PollError> {
    let path = RciPath::from_segments(segments).map_err(|_error| PollError::Request)?;
    match client
        .show(&path, &())
        .await
        .map_err(|_error| PollError::Request)?
    {
        RciBody::Json(response) => Ok(response.value),
        RciBody::Text(_) | _ => Err(PollError::Request),
    }
}

/// Counts entries in a hotspot response.
fn count_clients(value: &Value) -> u64 {
    match value {
        Value::Array(items) => u64::try_from(items.len()).unwrap_or(u64::MAX),
        Value::Object(items) => u64::try_from(items.len()).unwrap_or(u64::MAX),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => 0,
    }
}
