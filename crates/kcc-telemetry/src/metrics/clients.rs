//! Client, DHCP, mesh and storage families (heavy cadence), and opt-in per-client series.

use alloc::collections::BTreeMap;

use kcc_app::{poller::Snapshot, settings::ClientLabel};
use serde_json::Value;

use super::{
    json::{count, first_number, flag, gauge, number, rows, text},
    sink::Sink,
};

/// Per-client export settings.
#[derive(Clone, Copy, Debug)]
pub(super) struct PerClient {
    /// Export per-client series.
    pub enabled: bool,
    /// Per-router cap.
    pub max: usize,
    /// Client label scheme.
    pub label: ClientLabel,
}

/// The access point a host is attached to: `ap`, else an `AccessPoint` interface id.
fn access_point(host: &Value) -> Option<&str> {
    text(host, "ap").or_else(|| {
        let interface = host.get("interface")?;
        interface
            .as_str()
            .or_else(|| text(interface, "id"))
            .filter(|id| id.contains("AccessPoint"))
    })
}

/// Whether a hotspot host is online.
fn online(host: &Value) -> bool {
    flag(host, "active")
        .or_else(|| flag(host, "link"))
        .unwrap_or(false)
}

/// Renders the heavy families; returns how many per-client series were dropped.
pub(super) fn heavy(
    sink: &Sink,
    router: &str,
    snapshot: &Snapshot,
    per_client: PerClient,
    pseudonyms: &mut BTreeMap<String, String>,
) -> u64 {
    let hosts = rows(&snapshot.hotspot);
    let online_count = hosts.iter().filter(|host| online(host)).count();
    let offline_count = hosts.len().saturating_sub(online_count);
    for (state, count) in [("online", online_count), ("offline", offline_count)] {
        sink.put("keenetic_clients", &[router, state], count_f64(count));
    }
    wifi(sink, router, snapshot, &hosts);
    if !snapshot.dhcp_bindings.is_null() {
        let leases = rows(&snapshot.dhcp_bindings).len();
        sink.put("keenetic_dhcp_leases", &[router], count_f64(leases));
    }
    for member in rows(&snapshot.mesh_members) {
        let label = ["known-host", "name", "id", "cid"]
            .iter()
            .find_map(|key| text(member, key));
        if let (Some(name), Some(up)) = (label, flag(member, "online")) {
            sink.put("keenetic_mesh_member_up", &[router, name], gauge(up));
        }
    }
    storage(sink, router, &snapshot.media);
    if per_client.enabled {
        clients(sink, router, &hosts, per_client, pseudonyms)
    } else {
        0
    }
}

/// Online clients per access point, with every known access point present.
fn wifi(sink: &Sink, router: &str, snapshot: &Snapshot, hosts: &[&Value]) {
    let interfaces = rows(&snapshot.interfaces_summary);
    let mut counts: BTreeMap<&str, usize> = interfaces
        .iter()
        .filter(|entry| text(entry, "type") == Some("AccessPoint"))
        .filter_map(|entry| text(entry, "id"))
        .map(|id| (id, 0))
        .collect();
    for host in hosts.iter().filter(|host| online(host)) {
        if let Some(ap) = access_point(host) {
            let count = counts.entry(ap).or_default();
            *count = count.saturating_add(1);
        }
    }
    for (ap, count) in counts {
        let radio = ap.split_once('/').map_or(ap, |(radio, _)| radio);
        let band = interfaces
            .iter()
            .find(|entry| text(entry, "id") == Some(radio))
            .and_then(|entry| text(entry, "band"))
            .unwrap_or("unknown");
        sink.put(
            "keenetic_wifi_clients",
            &[router, ap, band],
            count_f64(count),
        );
    }
}

/// Storage partitions of `show media`.
fn storage(sink: &Sink, router: &str, media: &Value) {
    for medium in rows(media) {
        let partitions = medium.get("partition").map_or_else(|| vec![medium], rows);
        for partition in partitions {
            let Some(label) = text(partition, "label").or_else(|| text(medium, "id")) else {
                continue;
            };
            if let Some(total) = first_number(partition, &["total", "size"]) {
                sink.put("keenetic_storage_total_bytes", &[router, label], total);
            }
            if let Some(free) = number(partition, "free") {
                sink.put("keenetic_storage_free_bytes", &[router, label], free);
            }
        }
    }
}

/// Per-client series for at most `per_client.max` clients (lowest MACs first).
fn clients(
    sink: &Sink,
    router: &str,
    hosts: &[&Value],
    per_client: PerClient,
    pseudonyms: &mut BTreeMap<String, String>,
) -> u64 {
    let mut keyed: Vec<(&str, &Value)> = hosts
        .iter()
        .filter_map(|host| text(host, "mac").map(|mac| (mac, *host)))
        .collect();
    keyed.sort_unstable_by(|left, right| left.0.cmp(right.0));
    let dropped = keyed.len().saturating_sub(per_client.max);
    for (mac, host) in keyed.into_iter().take(per_client.max) {
        let label = client_label(mac, host, per_client.label, pseudonyms);
        let labels = [router, label.as_str()];
        for (keys, name) in [
            (
                &["rxbytes", "rx"][..],
                "keenetic_client_receive_bytes_total",
            ),
            (
                &["txbytes", "tx"][..],
                "keenetic_client_transmit_bytes_total",
            ),
            (&["rssi"][..], "keenetic_client_signal_dbm"),
            (&["txrate", "speed"][..], "keenetic_client_link_speed_mbps"),
        ] {
            if let Some(value) = first_number(host, keys) {
                sink.put(name, &labels, value);
            }
        }
    }
    u64::try_from(dropped).unwrap_or(u64::MAX)
}

/// The label of one client: its name, a stable `client-N` pseudonym (the scheme of the MCP
/// `redact_clients` switch) or, only when configured, its MAC.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "ClientLabel is non_exhaustive; unknown schemes fall back to the pseudonym"
)]
fn client_label(
    mac: &str,
    host: &Value,
    scheme: ClientLabel,
    pseudonyms: &mut BTreeMap<String, String>,
) -> String {
    let named = match scheme {
        ClientLabel::Name => text(host, "name").map(str::to_owned),
        ClientLabel::Mac => Some(mac.to_owned()),
        // Pseudonym, and any future scheme until mapped: the privacy-safe default.
        _ => None,
    };
    named.unwrap_or_else(|| {
        let next = pseudonyms.len().saturating_add(1);
        pseudonyms
            .entry(mac.to_owned())
            .or_insert_with(|| format!("client-{next}"))
            .clone()
    })
}

/// A count as a gauge value.
fn count_f64(value: usize) -> f64 {
    count(u64::try_from(value).unwrap_or(u64::MAX))
}
