//! Subscriber-driven shared router polling.

extern crate alloc;

mod extended;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{fmt, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use kcc_rci::{RciBody, RciClient, RciError, RciPath, capabilities::RouterInfo};
use serde_json::{Map, Value, json};
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
    /// `show interface stat` of every Internet-facing interface, keyed by interface id
    /// and refreshed on the light cadence; interfaces whose counters could not be read
    /// are absent.
    pub interface_stats: Value,
    /// Unix timestamp in seconds when this snapshot completed.
    pub fetched_at: u64,
    /// `show internet status`, refreshed on the light cadence while a metrics
    /// subscription is active; `Null` otherwise.
    pub internet_status: Value,
    /// `show interface stat` of every interface in state `up`, keyed by interface id and
    /// refreshed on the light cadence while a metrics subscription is active; an empty
    /// object otherwise.
    pub interface_counters: Value,
    /// `show ip hotspot`, refreshed on the heavy cadence.
    pub hotspot: Value,
    /// `show ip dhcp bindings`, heavy cadence, metrics subscription only; `Null` otherwise.
    pub dhcp_bindings: Value,
    /// `show media`, heavy cadence, metrics subscription only; `Null` otherwise.
    pub media: Value,
    /// `show mws member`, heavy cadence, metrics subscription only; `Null` otherwise.
    pub mesh_members: Value,
    /// Cached firmware-update flag recorded through [`Poller::record_update_available`];
    /// never read from the router by the poller.
    pub update_available: Option<bool>,
    /// Age of the heavy items (and `info`) when this snapshot was published.
    pub heavy_age: Duration,
    /// Wall time this polling round took.
    pub poll_duration: Duration,
}

/// Cadence of a permanent metrics subscription (see [`Poller::subscribe_metrics`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct MetricsCadence {
    /// Light-item refresh period.
    pub light: Duration,
    /// Heavy-item refresh period.
    pub heavy: Duration,
}

impl MetricsCadence {
    /// Creates a cadence from the `[metrics] interval` and `heavy_interval`.
    #[inline]
    #[must_use]
    pub const fn new(light: Duration, heavy: Duration) -> Self {
        Self { light, heavy }
    }
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
    /// The router refused the polling client's login.
    #[error("router refused the polling login")]
    Auth,
}

impl From<RegistryError> for PollError {
    #[inline]
    fn from(error: RegistryError) -> Self {
        if matches!(error, RegistryError::Rci(RciError::Auth(_))) {
            Self::Auth
        } else {
            Self::Registry {
                reason: error.to_string(),
            }
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
    #[inline]
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
    /// Permanent metrics subscriptions.
    metrics: Mutex<BTreeMap<String, MetricsCadence>>,
    /// Cached firmware-update flags.
    update_flags: Mutex<BTreeMap<String, bool>>,
    /// Poll timing.
    intervals: PollIntervals,
}

impl fmt::Debug for Poller {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Poller")
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
            metrics: Mutex::new(BTreeMap::new()),
            update_flags: Mutex::new(BTreeMap::new()),
            intervals,
        })
    }

    /// Subscribes to one router, starting its sole polling task lazily.
    ///
    /// The task polls while any receiver is alive, so a receiver held for the process
    /// lifetime keeps the router polled; the notifier relies on that.
    // cancel-safe: channel setup has no external side effect beyond starting a read-only task.
    #[inline]
    pub async fn subscribe(self: &Arc<Self>, router: &str) -> watch::Receiver<Option<PollResult>> {
        let mut channels = self.channels.lock().await;
        if let Some(sender) = channels.get(router) {
            return sender.subscribe();
        }
        let (sender, receiver) = watch::channel(None);
        drop(channels.insert(router.to_owned(), sender));
        drop(channels);
        let owner = Arc::clone(self);
        let router_id = router.to_owned();
        drop(tokio::spawn(async move {
            owner.run(router_id).await;
        }));
        receiver
    }

    /// Registers a permanent metrics subscription for `router` and subscribes to it.
    ///
    /// The router's single polling task then never idles out, refreshes the light items
    /// every `cadence.light` and the heavy items every `cadence.heavy` (or faster while UI
    /// subscribers want the default cadence), and also fetches the metrics-only items
    /// ([`Snapshot::internet_status`], [`Snapshot::interface_counters`],
    /// [`Snapshot::dhcp_bindings`], [`Snapshot::media`], [`Snapshot::mesh_members`]).
    /// The caller holds the returned receiver for the lifetime of the subscription: it is
    /// counted as the metrics subscriber, not as a UI subscriber.
    // cancel-safe: the registration is a map insert; subscribing only starts a read-only task.
    #[inline]
    pub async fn subscribe_metrics(
        self: &Arc<Self>,
        router: &str,
        cadence: MetricsCadence,
    ) -> watch::Receiver<Option<PollResult>> {
        let _previous: Option<MetricsCadence> =
            self.metrics.lock().await.insert(router.to_owned(), cadence);
        self.subscribe(router).await
    }

    /// Removes the permanent metrics subscription of `router`; the polling task then
    /// idles out as usual once no UI subscriber is left.
    // cancel-safe: a single map removal.
    #[inline]
    pub async fn unsubscribe_metrics(&self, router: &str) {
        let _removed: Option<MetricsCadence> = self.metrics.lock().await.remove(router);
    }

    /// Records the cached firmware-update flag published in [`Snapshot::update_available`]
    /// and applies it to the snapshot already published, so subscribers see it before the
    /// next round.
    // NOT cancel-safe: cancelled between the two lock awaits, the flag is stored but never
    // published to the watch channel.
    #[inline]
    pub async fn record_update_available(&self, router: &str, available: bool) {
        let _previous: Option<bool> = self
            .update_flags
            .lock()
            .await
            .insert(router.to_owned(), available);
        if let Some(sender) = self.channels.lock().await.get(router) {
            let _modified: bool = sender.send_if_modified(|published| match published {
                Some(Ok(snapshot)) if snapshot.update_available != Some(available) => {
                    snapshot.update_available = Some(available);
                    true
                }
                Some(_) | None => false,
            });
        }
    }

    /// The latest result published for `router`, without subscribing: `None` when no
    /// polling task follows the router or its first round has not completed.
    // cancel-safe: one map read.
    #[inline]
    pub async fn latest(&self, router: &str) -> Option<PollResult> {
        self.channels
            .lock()
            .await
            .get(router)
            .and_then(|sender| sender.borrow().clone())
    }

    /// Returns completed light polling rounds for observability and cadence tests.
    // cancel-safe: reads a counter under a lock; cancellation changes nothing.
    #[inline]
    pub async fn light_rounds(&self, router: &str) -> u64 {
        self.light_rounds
            .lock()
            .await
            .get(router)
            .copied()
            .unwrap_or(0)
    }

    /// Runs one router loop until it has stayed idle for the configured timeout.
    // NOT cancel-safe: it runs as the router's only polling task; aborted, it leaves the router's
    // channel entry registered with no task polling it, so later subscribers wait for snapshots
    // that never come.
    async fn run(self: Arc<Self>, router: String) {
        let mut heavy: Option<extended::HeavyItems> = None;
        let mut idle_since = None;
        loop {
            let entry = {
                let channels = self.channels.lock().await;
                channels.get(&router).cloned()
            };
            let Some(sender) = entry else {
                return;
            };
            let metrics = self.metrics.lock().await.get(&router).copied();
            let receivers = sender.receiver_count();
            if receivers == 0 && metrics.is_none() {
                let since = idle_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= self.intervals.idle {
                    if self.retire(&router).await {
                        return;
                    }
                    idle_since = None;
                    continue;
                }
                sleep(self.intervals.light.min(self.intervals.idle)).await;
                continue;
            }
            idle_since = None;
            let round = extended::round(
                &self.intervals,
                metrics,
                receivers > usize::from(metrics.is_some()),
            );
            let result = self.fetch(&router, &mut heavy, round).await;
            if result.is_ok() {
                let mut rounds = self.light_rounds.lock().await;
                let count = rounds.entry(router.clone()).or_default();
                *count = count.saturating_add(1);
                drop(rounds);
            }
            let delay = if result.is_ok() {
                round.light
            } else {
                self.intervals.error
            };
            drop(sender.send(Some(result)));
            sleep(delay).await;
        }
    }

    /// Removes the idle router's channel entry unless a subscriber arrived since the idle
    /// decision; the check and the removal share one hold of the `channels` lock, the lock
    /// `subscribe` takes, so no receiver can be handed out for a removed entry.
    // cancel-safe: one map removal.
    async fn retire(&self, router: &str) -> bool {
        let mut channels = self.channels.lock().await;
        if channels
            .get(router)
            .is_some_and(|sender| sender.receiver_count() > 0)
        {
            return false;
        }
        drop(channels.remove(router));
        true
    }

    /// Fetches one snapshot, reusing heavy values until their cadence expires.
    ///
    /// # Errors
    /// [`PollError`] when the router client cannot be built or a required read fails.
    // NOT cancel-safe: it only reads router state; the heavy-item cache it refreshes is replaced
    // whole, but it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
    // session.
    async fn fetch(
        &self,
        router: &str,
        heavy: &mut Option<extended::HeavyItems>,
        round: extended::Round,
    ) -> PollResult {
        let started = Instant::now();
        let client = self.registry.poll_client(router).await?;
        let refresh_heavy = heavy.as_ref().is_none_or(|items| {
            items.fetched.elapsed() >= round.heavy || items.extended != round.extended
        });
        if refresh_heavy {
            *heavy =
                Some(extended::fetch_heavy(&self.registry, router, &client, round.extended).await?);
        }
        let items = heavy.as_ref().ok_or(PollError::Request)?;
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
        let (internet_status, interfaces_summary, interface_stats, interface_counters) =
            if round.extended {
                let status = show_json(&client, &["show", "internet", "status"])
                    .await
                    .unwrap_or(Value::Null);
                let interfaces = show_json(&client, &["show", "interface"])
                    .await
                    .unwrap_or(Value::Null);
                let counters = extended::up_interface_counters(&client, &interfaces).await;
                let wan = extended::wan_subset(&counters, &wan_interface_ids(&interfaces));
                (status, interfaces, wan, counters)
            } else {
                let wan = wan_stats(&client, &items.interfaces).await;
                (Value::Null, items.interfaces.clone(), wan, json!({}))
            };
        Ok(Snapshot {
            info: items.info.clone(),
            system,
            internet,
            clients_count: count_clients(&items.hotspot),
            interfaces_summary,
            wifi_summary,
            last_change,
            interface_stats,
            fetched_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs()),
            internet_status,
            interface_counters,
            hotspot: items.hotspot.clone(),
            dhcp_bindings: items.dhcp_bindings.clone(),
            media: items.media.clone(),
            mesh_members: items.mesh_members.clone(),
            update_available: self.update_flags.lock().await.get(router).copied(),
            heavy_age: items.fetched.elapsed(),
            poll_duration: started.elapsed(),
        })
    }
}

/// Ids of the interfaces a `show interface` response marks as Internet-facing
/// (`global` or `defaultgw`), in response order.
#[must_use]
#[inline]
pub fn wan_interface_ids(interfaces: &Value) -> Vec<String> {
    let entries: Vec<&Value> = match interfaces {
        Value::Object(map) => map.values().collect(),
        Value::Array(items) => items.iter().collect(),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Vec::new(),
    };
    entries
        .into_iter()
        .filter(|entry| {
            ["global", "defaultgw"]
                .iter()
                .any(|flag| entry.get(*flag).and_then(Value::as_bool) == Some(true))
        })
        .filter_map(|entry| entry.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

/// Reads `show interface stat` for every Internet-facing interface.
// NOT cancel-safe: it only reads interface counters, but it may sign in first, and a sign-in
// dropped mid-way can leave an orphaned router session.
async fn wan_stats(client: &RciClient, interfaces: &Value) -> Value {
    let mut stats = Map::new();
    let Ok(path) = RciPath::from_segments(["show", "interface", "stat"]) else {
        return Value::Object(stats);
    };
    for id in wan_interface_ids(interfaces) {
        if let Ok(RciBody::Json(response)) = client.show(&path, &[("name", id.as_str())]).await {
            drop(stats.insert(id, response.value));
        }
    }
    Value::Object(stats)
}

/// Reads one JSON show resource.
///
/// # Errors
/// [`PollError::Auth`] when the router refuses the login, else [`PollError::Request`] when
/// the path is invalid, the read fails or the answer is not JSON.
// NOT cancel-safe: it only sends one `show` read, but it may sign in first, and a sign-in dropped
// mid-way can leave an orphaned router session.
async fn show_json(client: &RciClient, segments: &[&str]) -> Result<Value, PollError> {
    let path = RciPath::from_segments(segments).map_err(|_error| PollError::Request)?;
    match client.show(&path, &()).await.map_err(|error| {
        if matches!(error, RciError::Auth(_)) {
            PollError::Auth
        } else {
            PollError::Request
        }
    })? {
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

#[cfg(test)]
mod retire_tests;

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use serde_json::json;

    use super::wan_interface_ids;

    /// Only interfaces flagged `global` or `defaultgw` get counters, in either response shape.
    #[test]
    fn wan_interfaces_are_the_global_and_default_gateway_ones() {
        let keyed = json!({
            "Bridge0": {"id": "Bridge0", "global": false},
            "ISP": {"id": "ISP", "global": true, "defaultgw": true},
            "PPPoE0": {"id": "PPPoE0", "defaultgw": true},
            "Wireguard0": {"id": "Wireguard0"}
        });
        assert_eq!(wan_interface_ids(&keyed), ["ISP", "PPPoE0"], "object form");
        let listed = json!([{"id": "GigabitEthernet1", "global": true}, {"id": "Bridge0"}]);
        assert_eq!(
            wan_interface_ids(&listed),
            ["GigabitEthernet1"],
            "array form"
        );
        assert!(wan_interface_ids(&json!(null)).is_empty(), "absent");
    }
}
