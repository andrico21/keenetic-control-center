//! Round planning, heavy-item caching and the items read only for a metrics subscription.

use core::time::Duration;
use std::{
    sync::{LazyLock, Mutex, PoisonError},
    time::Instant as WallInstant,
};

use kcc_rci::{Admit, Deduper, RciBody, RciClient, RciPath, capabilities::RouterInfo};
use serde_json::{Map, Value, json};
use tokio::time::Instant;

use super::{MetricsCadence, PollError, PollIntervals, show_json};
use crate::registry::RouterRegistry;

/// Collapses repeated fallback lines of the same router and item.
static SEEN: LazyLock<Mutex<Deduper>> = LazyLock::new(|| Mutex::new(Deduper::default()));

/// `read`, or `fallback` once the missing item is logged for the router of `client`.
fn or_logged(
    read: Result<Value, PollError>,
    fallback: Value,
    (client, item): (&RciClient, &str),
) -> Value {
    read.unwrap_or_else(|error| {
        let key = (
            client.log_id().to_owned(),
            "show".to_owned(),
            item.to_owned(),
            error.class().to_owned(),
        );
        let admit = SEEN
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .admit(key, WallInstant::now());
        if let Admit::Log { suppressed } = admit {
            tracing::debug!(
                router = %client.log_id(),
                item = %item,
                cause = %error.class(),
                suppressed,
                "telemetry item unavailable, using an empty value"
            );
        }
        fallback
    })
}

/// Timing and item set of one polling round.
#[derive(Clone, Copy, Debug)]
pub(super) struct Round {
    /// Delay until the next light round.
    pub light: Duration,
    /// Maximum age of heavy items.
    pub heavy: Duration,
    /// Fetch the metrics-only items.
    pub extended: bool,
}

/// Heavy-cadence items cached between light rounds.
#[derive(Debug)]
pub(super) struct HeavyItems {
    /// Detected identity.
    pub info: RouterInfo,
    /// `show interface` (used on the heavy cadence without a metrics subscription).
    pub interfaces: Value,
    /// `show ip hotspot`.
    pub hotspot: Value,
    /// `show ip dhcp bindings`.
    pub dhcp_bindings: Value,
    /// `show media`.
    pub media: Value,
    /// `show mws member`.
    pub mesh_members: Value,
    /// Whether the metrics-only items were fetched.
    pub extended: bool,
    /// When these items were fetched.
    pub fetched: Instant,
}

/// Picks the cadence and item set: UI subscribers get the default cadence, a metrics
/// subscription its own (the faster of the two wins when both are present).
pub(super) fn round(
    intervals: &PollIntervals,
    metrics: Option<MetricsCadence>,
    ui_subscribed: bool,
) -> Round {
    match (metrics, ui_subscribed) {
        (None, _) => Round {
            light: intervals.light,
            heavy: intervals.heavy,
            extended: false,
        },
        (Some(cadence), false) => Round {
            light: cadence.light,
            heavy: cadence.heavy,
            extended: true,
        },
        (Some(cadence), true) => Round {
            light: cadence.light.min(intervals.light),
            heavy: cadence.heavy.min(intervals.heavy),
            extended: true,
        },
    }
}

/// Fetches the heavy-cadence items; `show interface` only without a metrics
/// subscription (with one it is a light item).
///
/// # Errors
/// [`PollError`] when the router cannot be detected or a required read fails.
// NOT cancel-safe: it only reads router state, but it may sign in first, and a sign-in dropped
// mid-way can leave an orphaned router session.
pub(super) async fn fetch_heavy(
    registry: &RouterRegistry,
    router: &str,
    client: &RciClient,
    extended: bool,
) -> Result<HeavyItems, PollError> {
    let info = registry.poll_info(router).await?;
    let interfaces = if extended {
        Value::Null
    } else {
        let interfaces = show_json(client, &["show", "interface"]).await;
        or_logged(interfaces, Value::Null, (client, "show interface"))
    };
    let listed = show_json(client, &["show", "ip", "hotspot"]).await;
    let hotspot = or_logged(listed, json!({}), (client, "show ip hotspot"));
    let (dhcp_bindings, media, mesh_members) = if extended {
        heavy_items(client).await
    } else {
        (Value::Null, Value::Null, Value::Null)
    };
    Ok(HeavyItems {
        info,
        interfaces,
        hotspot,
        dhcp_bindings,
        media,
        mesh_members,
        extended,
        fetched: Instant::now(),
    })
}

/// Ids of the interfaces a `show interface` response reports in state `up`.
fn up_interface_ids(interfaces: &Value) -> Vec<String> {
    let entries: Vec<&Value> = match interfaces {
        Value::Object(map) => map.values().collect(),
        Value::Array(items) => items.iter().collect(),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Vec::new(),
    };
    entries
        .into_iter()
        .filter(|entry| entry.get("state").and_then(Value::as_str) == Some("up"))
        .filter_map(|entry| entry.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

/// Reads `show interface stat` of every up interface, keyed by interface id.
///
/// Uses a plain GET per interface: an interface without counters answers 404 and is
/// skipped, and the request never takes the query-less POST fallback of
/// [`RciClient::show`], which would return the whole table.
// NOT cancel-safe: it only reads interface counters, but it may sign in first, and a sign-in
// dropped mid-way can leave an orphaned router session.
pub(super) async fn up_interface_counters(client: &RciClient, interfaces: &Value) -> Value {
    let mut counters = Map::new();
    let Ok(path) = RciPath::from_segments(["show", "interface", "stat"]) else {
        return Value::Object(counters);
    };
    for id in up_interface_ids(interfaces) {
        if let Ok(RciBody::Json(response)) = client.get(&path, &[("name", id.as_str())]).await {
            drop(counters.insert(id, response.value));
        }
    }
    Value::Object(counters)
}

/// The entries of `counters` whose key is one of `ids`.
pub(super) fn wan_subset(counters: &Value, ids: &[String]) -> Value {
    Value::Object(
        ids.iter()
            .filter_map(|id| {
                counters
                    .get(id.as_str())
                    .map(|value| (id.clone(), value.clone()))
            })
            .collect(),
    )
}

/// Reads `show ip dhcp bindings`, `show media` and `show mws member`; unreadable items
/// are `Null`.
// NOT cancel-safe: it only sends `show` reads, but it may sign in first, and a sign-in dropped
// mid-way can leave an orphaned router session.
pub(super) async fn heavy_items(client: &RciClient) -> (Value, Value, Value) {
    let bindings = show_json(client, &["show", "ip", "dhcp", "bindings"]).await;
    let dhcp = or_logged(bindings, Value::Null, (client, "show ip dhcp bindings"));
    let volumes = show_json(client, &["show", "media"]).await;
    let media = or_logged(volumes, Value::Null, (client, "show media"));
    let members = show_json(client, &["show", "mws", "member"]).await;
    let mesh = or_logged(members, Value::Null, (client, "show mws member"));
    (dhcp, media, mesh)
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation and fails by panicking"
)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::{error::Error, net::SocketAddr};

    use kcc_rci::RciClient;
    use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, FaultInjection, log_capture, model::Profile};
    use serde_json::{Value, json};
    use tempfile::TempDir;
    use url::Url;

    use super::{heavy_items, or_logged, up_interface_ids, wan_subset};
    use crate::{
        permissions::{Permission, Role},
        persist::StateStore,
        poller::PollError,
        registry::{ManagedRouterProfile, RouterRegistry},
        settings::OutboundConfig,
    };

    /// A client for the fake router at `address`, registered as `id`.
    async fn client_of(
        directory: &TempDir,
        id: &str,
        address: SocketAddr,
    ) -> Result<Arc<RciClient>, Box<dyn Error>> {
        let password =
            kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
        let outbound = OutboundConfig {
            allow_loopback: true,
            ..OutboundConfig::default()
        };
        let registry = Arc::new(RouterRegistry::new(
            StateStore::open(&directory.path().join("state"))?,
            &[],
            &outbound,
        )?);
        let profile = ManagedRouterProfile::new(
            id.to_owned(),
            Url::parse(&format!("http://{address}"))?,
            "admin".to_owned(),
            password,
        );
        let admin = Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]);
        registry.create(&admin, profile).await?;
        Ok(registry.client(id).await?)
    }

    /// Todo 9: the same item failing for two different causes is logged once per cause,
    /// each line naming its own cause class.
    #[tokio::test]
    async fn distinct_causes_of_one_item_are_each_logged() -> Result<(), Box<dyn Error>> {
        let (captured, _guard) = log_capture::start();
        let directory = TempDir::new()?;
        let (address, handle) = FakeRouter::builder(Profile::default())
            .build()?
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let client = client_of(&directory, "cause-router", address).await?;

        for cause in ["http_500", "timeout", "http_500"] {
            let read = Err(PollError::request(cause));
            let value = or_logged(read, Value::Null, (&client, "show media"));
            assert_eq!(value, Value::Null, "the fallback is returned");
        }

        let lines: Vec<String> = captured
            .lines_at("DEBUG")
            .into_iter()
            .filter(|line| line.contains("telemetry item unavailable"))
            .collect();
        assert_eq!(lines.len(), 2, "{lines:?}");
        let causes: Vec<bool> = [("cause=http_500"), ("cause=timeout")]
            .iter()
            .zip(&lines)
            .map(|(cause, line)| line.contains(cause))
            .collect();
        assert_eq!(causes, [true, true], "{lines:?}");
        handle.shutdown().await?;
        Ok(())
    }

    /// Todo 9: an item that falls back to `Null` is logged at DEBUG once per router and
    /// item however often it is read, and the other items stay unaffected.
    #[tokio::test]
    async fn a_missing_item_logs_its_cause_once_per_item() -> Result<(), Box<dyn Error>> {
        let (captured, _guard) = log_capture::start();
        let directory = TempDir::new()?;
        let fake = FakeRouter::builder(Profile::default())
            .faults(FaultInjection::default().fail_read_matching("show/media", 100))
            .build()?;
        let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
        let client = client_of(&directory, "lab-router", address).await?;

        let first = heavy_items(&client).await;
        let second = heavy_items(&client).await;

        assert_eq!(
            (first.1, second.1),
            (Value::Null, Value::Null),
            "media falls back"
        );
        assert!(
            first.0.is_array() || first.0.is_object(),
            "other items are read"
        );
        let lines: Vec<String> = captured
            .lines_at("DEBUG")
            .into_iter()
            .filter(|line| line.contains("telemetry item unavailable"))
            .collect();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines.iter().all(|line| line.contains("router=lab-router")
                && line.contains("item=show media")
                && line.contains("cause=http_500")),
            "{lines:?}"
        );
        handle.shutdown().await?;
        Ok(())
    }

    /// Only interfaces in state `up` get counters; the WAN subset keeps the given ids.
    #[test]
    fn up_interfaces_and_wan_subset() {
        let interfaces = json!({
            "ISP": {"id": "ISP", "state": "up", "global": true},
            "Port1": {"id": "Port1", "state": "down"},
            "Bridge0": {"id": "Bridge0", "state": "up"}
        });
        assert_eq!(up_interface_ids(&interfaces), ["Bridge0", "ISP"], "up only");
        let counters = json!({"ISP": {"rxbytes": 1_u8}, "Bridge0": {"rxbytes": 2_u8}});
        assert_eq!(
            wan_subset(&counters, &["ISP".to_owned(), "Gone".to_owned()]),
            json!({"ISP": {"rxbytes": 1_u8}}),
            "subset"
        );
    }
}
