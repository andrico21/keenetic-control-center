//! Round planning, heavy-item caching and the items read only for a metrics subscription.

use core::time::Duration;

use kcc_rci::{RciBody, RciClient, RciPath, capabilities::RouterInfo};
use serde_json::{Map, Value, json};
use tokio::time::Instant;

use super::{MetricsCadence, PollError, PollIntervals, show_json};
use crate::registry::RouterRegistry;

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
        show_json(client, &["show", "interface"])
            .await
            .unwrap_or(Value::Null)
    };
    let hotspot = show_json(client, &["show", "ip", "hotspot"])
        .await
        .unwrap_or_else(|_| json!({}));
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
pub(super) async fn heavy_items(client: &RciClient) -> (Value, Value, Value) {
    let dhcp = show_json(client, &["show", "ip", "dhcp", "bindings"])
        .await
        .unwrap_or(Value::Null);
    let media = show_json(client, &["show", "media"])
        .await
        .unwrap_or(Value::Null);
    let mesh = show_json(client, &["show", "mws", "member"])
        .await
        .unwrap_or(Value::Null);
    (dhcp, media, mesh)
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use serde_json::json;

    use super::{up_interface_ids, wan_subset};

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
