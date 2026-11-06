//! Interface and WireGuard projections.

use core::fmt::Write as _;

use md5::{Digest as _, Md5};
use serde_json::{Map, Value, json};

use super::matching;

/// Projects configured interfaces and WireGuard peer details.
pub(super) fn interfaces(command_lines: &[Vec<String>]) -> Value {
    let mut result = Map::new();
    for words in matching(command_lines, &["interface"]) {
        let Some((name, command)) = words.split_first() else {
            continue;
        };
        let entry = result
            .entry(name.clone())
            .or_insert_with(|| json!({"id":name,"interface-name":name}));
        let Some(fields) = entry.as_object_mut() else {
            continue;
        };
        match command {
            [field, value]
                if matches!(field.as_str(), "description" | "ssid" | "security-level") =>
            {
                drop(fields.insert(field.clone(), Value::String(value.clone())));
            }
            [state] if matches!(state.as_str(), "up" | "down") => {
                drop(fields.insert("state".to_owned(), Value::String(state.clone())));
            }
            [authentication, wpa_psk, marker]
                if authentication == "authentication"
                    && wpa_psk == "wpa-psk"
                    && marker == "ns3" =>
            {
                drop(fields.insert("authentication".to_owned(), json!({"wpa-psk":{"ns3":true}})));
            }
            [wireguard, private_key]
                if wireguard == "wireguard" && private_key == "private-key" =>
            {
                wireguard_identity(fields, name);
                drop(fields.insert("private-key".to_owned(), json!({"present":true})));
            }
            [wireguard, private_key, _]
                if wireguard == "wireguard" && private_key == "private-key" =>
            {
                wireguard_identity(fields, name);
                drop(fields.insert("private-key".to_owned(), json!({"present":true})));
            }
            [wireguard, listen_port, port]
                if wireguard == "wireguard" && listen_port == "listen-port" =>
            {
                wireguard_identity(fields, name);
                drop(fields.insert("listen-port".to_owned(), Value::String(port.clone())));
            }
            [wireguard, peer, key, tail @ ..] if wireguard == "wireguard" && peer == "peer" => {
                wireguard_identity(fields, name);
                peer_field(fields, key, tail);
            }
            _ => {}
        }
    }
    Value::Object(result)
}

/// Adds deterministic public identity without exposing private-key material.
fn wireguard_identity(fields: &mut Map<String, Value>, name: &str) {
    drop(fields.insert("type".to_owned(), Value::String("Wireguard".to_owned())));
    let digest = Md5::digest(name.as_bytes());
    let mut public_key = String::from("fake-");
    for byte in digest {
        let _result = write!(public_key, "{byte:02x}");
    }
    drop(fields.insert("public-key".to_owned(), Value::String(public_key)));
}

/// Adds one non-secret peer property or a secret-presence marker.
fn peer_field(fields: &mut Map<String, Value>, key: &str, tail: &[String]) {
    let peers_entry = fields
        .entry("peers".to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(peers) = peers_entry.as_object_mut() else {
        return;
    };
    let selected = peers
        .entry(key.to_owned())
        .or_insert_with(|| json!({"public-key":key}));
    let Some(peer) = selected.as_object_mut() else {
        return;
    };
    match tail {
        [field, values @ ..]
            if matches!(
                field.as_str(),
                "endpoint" | "allow-ips" | "keepalive-interval"
            ) =>
        {
            drop(peer.insert(
                field.clone(),
                Value::Array(values.iter().cloned().map(Value::String).collect()),
            ));
        }
        [field, ..] if field == "preshared-key" => {
            drop(peer.insert("preshared-key".to_owned(), json!({"present":true})));
        }
        _ => {}
    }
}
