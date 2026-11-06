//! Interface, radio and WireGuard families.

use kcc_app::poller::Snapshot;
use serde_json::Value;

use super::{
    json::{first_number, flag, gauge, number, rows, text},
    sink::Sink,
};

/// `show interface stat` members per counter family.
const COUNTERS: &[(&[&str], &str)] = &[
    (&["rxbytes"], "keenetic_interface_receive_bytes_total"),
    (&["txbytes"], "keenetic_interface_transmit_bytes_total"),
    (&["rxpackets"], "keenetic_interface_receive_packets_total"),
    (&["txpackets"], "keenetic_interface_transmit_packets_total"),
    (
        &["rxerrors", "rx-errors"],
        "keenetic_interface_receive_errors_total",
    ),
    (
        &["txerrors", "tx-errors"],
        "keenetic_interface_transmit_errors_total",
    ),
];

/// Renders the interface families of one fresh snapshot.
pub(super) fn light(sink: &Sink, router: &str, snapshot: &Snapshot) {
    for entry in rows(&snapshot.interfaces_summary) {
        let Some(id) = text(entry, "id") else {
            continue;
        };
        let kind = text(entry, "type").unwrap_or_default();
        if let Some(up) = flag(entry, "state") {
            sink.put(
                "keenetic_interface_up",
                &[
                    router,
                    id,
                    kind,
                    text(entry, "description").unwrap_or_default(),
                ],
                gauge(up),
            );
        }
        if let Some(link) = flag(entry, "link") {
            sink.put("keenetic_interface_link_up", &[router, id], gauge(link));
        }
        if let Some(uptime) = number(entry, "uptime") {
            sink.put("keenetic_interface_uptime_seconds", &[router, id], uptime);
        }
        if kind == "WifiMaster"
            && let Some(celsius) = number(entry, "temperature")
        {
            sink.put("keenetic_radio_temperature_celsius", &[router, id], celsius);
        }
        if let Some(wireguard) = entry.get("wireguard") {
            peers(sink, router, id, wireguard);
        }
    }
    if let Value::Object(counters) = &snapshot.interface_counters {
        for (id, stats) in counters {
            for (keys, name) in COUNTERS {
                if let Some(total) = first_number(stats, keys) {
                    sink.put(name, &[router, id], total);
                }
            }
        }
    }
}

/// WireGuard peers of one interface; the peer label is the first 8 characters of its
/// public key.
fn peers(sink: &Sink, router: &str, interface: &str, wireguard: &Value) {
    for peer in rows(wireguard.get("peer").unwrap_or(&Value::Null)) {
        let (Some(key), Some(seconds)) = (
            text(peer, "public-key"),
            first_number(peer, &["last-handshake", "last_handshake"]),
        ) else {
            continue;
        };
        let short: String = key.chars().take(8).collect();
        sink.put(
            "keenetic_wireguard_peer_last_handshake_seconds",
            &[router, interface, &short],
            seconds,
        );
    }
}
