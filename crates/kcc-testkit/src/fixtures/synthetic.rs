//! Deterministic synthetic show data shared by every model profile.

use serde_json::{Map, Value, json};

use crate::model::Model;

/// Adds all generated domain fixtures to a model seed.
pub(super) fn enrich(show: &mut Value, model: Model) {
    let Some(root) = show.as_object_mut() else {
        return;
    };
    enrich_interfaces(root, model);
    let fixtures = [
        ("ip/hotspot", hotspot()),
        ("ip/dhcp/bindings", client_rows("bound")),
        ("ip/arp", client_rows("reachable")),
        ("associations", associations()),
        ("interface/stat", interface_stats()),
        (
            "ip/policy",
            json!([{"name":"Policy0","description":"Default fixture policy","permit":true}]),
        ),
        (
            "ipv6/route",
            json!([{"destination":"2001:db8:1::/48","gateway":"2001:db8::1","interface":"ISP","metric":10_u8}]),
        ),
        ("ip/nat", nat_rows()),
        (
            "internet/status",
            json!({"enabled":true,"reliable":true,"internet":true,"gateway-accessible":true,"dns-accessible":true,"host-accessible":true,"captive-accessible":false}),
        ),
        (
            "dns-proxy",
            json!({"cache-size":1024_u16,"rebind-protect":true,"tls":{"upstream":[]},"https":{"upstream":[]}}),
        ),
        (
            "media",
            json!([{"id":"Media0","label":"fixture-media","uuid":"0f1e2d3c-4b5a-4978-8796-a5b4c3d2e1f0","filesystem":"ext4","size":8_000_000_000_u64,"free":6_000_000_000_u64,"initialize-supported":["default","ext4","ntfs"]}]),
        ),
        (
            "usb",
            json!([{"id":"Usb0","vendor":"fixture-vendor","product":"fixture-storage","connected":true}]),
        ),
        (
            "schedule",
            json!([{"name":"Schedule0","description":"Fixture schedule","active":true}]),
        ),
        (
            "ndns",
            json!({"name":"router.fixture.invalid","status":"registered","booked":true}),
        ),
        (
            "mws/member",
            json!([{"id":"Extender0","name":"fixture-extender","mac":"02:00:00:00:20:01","online":true}]),
        ),
        (
            "upnp/redirect",
            json!([{"protocol":"tcp","external-port":40000_u16,"internal-address":"192.0.2.40","internal-port":40000_u16,"description":"fixture redirect"}]),
        ),
    ];
    for (key, value) in fixtures {
        drop(root.insert(key.to_owned(), value));
    }
}

/// Adds radios and access points while retaining seeded interfaces.
fn enrich_interfaces(root: &mut Map<String, Value>, model: Model) {
    let Some(interfaces) = root.get_mut("interface").and_then(Value::as_object_mut) else {
        return;
    };
    let next = interfaces.len();
    let entries = [
        ("WifiMaster0", radio("WifiMaster0", next, "2.4", 1_u8)),
        (
            "WifiMaster1",
            radio("WifiMaster1", next.saturating_add(1), "5", 36_u8),
        ),
        (
            "WifiMaster1/AccessPoint0",
            access_point("WifiMaster1/AccessPoint0", next.saturating_add(2), "ssid-5"),
        ),
        (
            "WifiMaster0/AccessPoint1",
            access_point(
                "WifiMaster0/AccessPoint1",
                next.saturating_add(3),
                "ssid-guest",
            ),
        ),
    ];
    for (name, value) in entries {
        drop(interfaces.insert(name.to_owned(), value));
    }
    let address = match model {
        Model::Kn1811 => "203.0.113.11",
        Model::Kn1010 => "203.0.113.12",
        Model::Kn3810 => "203.0.113.13",
        Model::Nc3013 => "203.0.113.14",
    };
    if let Some(wan) = interfaces.get_mut("ISP").and_then(Value::as_object_mut) {
        drop(wan.insert("address".to_owned(), Value::String(address.to_owned())));
    }
}

/// Builds one radio interface.
fn radio(id: &str, index: usize, band: &str, channel: u8) -> Value {
    json!({"id":id,"index":index,"interface-name":id,"type":"WifiMaster","description":"Fixture radio","traits":["Wireless"],"link":"up","state":"up","mtu":1500_u16,"admin-only":false,"band":band,"channel":channel})
}

/// Builds one access-point interface.
fn access_point(id: &str, index: usize, ssid: &str) -> Value {
    json!({"id":id,"index":index,"interface-name":id,"type":"AccessPoint","description":"Fixture Wi-Fi","traits":["Wireless"],"link":"up","state":"up","mtu":1500_u16,"admin-only":false,"ssid":ssid})
}

/// Builds six wired and wireless hotspot clients.
fn hotspot() -> Value {
    json!([
        {"mac":"02:00:00:00:10:01","ip":"192.0.2.21","name":"wired-registered","interface":"Bridge0","registered":true,"access":"permit","policy":"Policy0","schedule":"Schedule0","rx":12000_u64,"tx":8000_u64,"link":"up"},
        {"mac":"02:00:00:00:10:02","ip":"192.0.2.22","name":"wired-unregistered","interface":"Bridge0","registered":false,"access":"permit","policy":"Policy0","schedule":"","rx":3000_u64,"tx":2000_u64,"link":"up"},
        {"mac":"02:00:00:00:10:03","ip":"192.0.2.23","name":"phone-registered","interface":"WifiMaster0/AccessPoint0","registered":true,"access":"permit","policy":"Policy0","schedule":"Schedule0","rx":45000_u64,"tx":21000_u64,"link":"up","rssi":-42_i8},
        {"mac":"02:00:00:00:10:04","ip":"192.0.2.24","name":"tablet-unregistered","interface":"WifiMaster0/AccessPoint1","registered":false,"access":"deny","policy":"Policy0","schedule":"","rx":9000_u64,"tx":4000_u64,"link":"up","rssi":-58_i8},
        {"mac":"02:00:00:00:10:05","ip":"192.0.2.25","name":"laptop-registered","interface":"WifiMaster1/AccessPoint0","registered":true,"access":"permit","policy":"Policy0","schedule":"Schedule0","rx":98000_u64,"tx":76000_u64,"link":"up","rssi":-37_i8},
        {"mac":"02:00:00:00:10:06","ip":"192.0.2.26","name":"guest-unregistered","interface":"WifiMaster1/AccessPoint0","registered":false,"access":"permit","policy":"Policy0","schedule":"","rx":7000_u64,"tx":5000_u64,"link":"up","rssi":-66_i8}
    ])
}

/// Builds client-address rows with safe synthetic identities.
fn client_rows(state: &str) -> Value {
    Value::Array(
        (1_u8..=6_u8)
            .map(|host| {
                json!({
                    "mac":format!("02:00:00:00:10:{host:02x}"),
                    "address":format!("192.0.2.{}", host.saturating_add(20)),
                    "interface":"Bridge0","state":state,"expires":3600_u16
                })
            })
            .collect(),
    )
}

/// Builds wireless association rows.
fn associations() -> Value {
    json!([
        {"mac":"02:00:00:00:10:03","interface":"WifiMaster0/AccessPoint0","ssid":"ssid-1","rssi":-42_i8,"rx-rate":144_u16,"tx-rate":144_u16},
        {"mac":"02:00:00:00:10:04","interface":"WifiMaster0/AccessPoint1","ssid":"ssid-guest","rssi":-58_i8,"rx-rate":72_u16,"tx-rate":65_u16},
        {"mac":"02:00:00:00:10:05","interface":"WifiMaster1/AccessPoint0","ssid":"ssid-5","rssi":-37_i8,"rx-rate":866_u16,"tx-rate":780_u16},
        {"mac":"02:00:00:00:10:06","interface":"WifiMaster1/AccessPoint0","ssid":"ssid-5","rssi":-66_i8,"rx-rate":173_u16,"tx-rate":130_u16}
    ])
}

/// Builds interface counters keyed by interface id.
fn interface_stats() -> Value {
    json!({
        "ISP":{"id":"ISP","rxbytes":123_456_789_u64,"txbytes":98_765_432_u64,"rxpackets":120_000_u64,"txpackets":98_000_u64},
        "Bridge0":{"id":"Bridge0","rxbytes":76_543_210_u64,"txbytes":45_678_901_u64,"rxpackets":76_000_u64,"txpackets":45_000_u64},
        "WifiMaster0":{"id":"WifiMaster0","rxbytes":23_456_789_u64,"txbytes":12_345_678_u64},
        "WifiMaster1":{"id":"WifiMaster1","rxbytes":34_567_890_u64,"txbytes":23_456_789_u64}
    })
}

/// Builds a large synthetic NAT table for pagination tests.
fn nat_rows() -> Value {
    Value::Array((0_u16..480_u16).map(|index| json!({
        "id":index,"protocol":if index.is_multiple_of(2) {"tcp"} else {"udp"},
        "source":format!("192.0.2.{}", index.checked_rem(200).unwrap_or_default().saturating_add(20)),"source-port":10000_u16.saturating_add(index),
        "destination":"203.0.113.200","destination-port":20000_u16.saturating_add(index),
        "translated-address":"198.51.100.200","translated-port":30000_u16.saturating_add(index),
        "interface":"ISP","state":"established","rxbytes":u64::from(index).saturating_mul(1000),
        "txbytes":u64::from(index).saturating_mul(700)
    })).collect())
}
