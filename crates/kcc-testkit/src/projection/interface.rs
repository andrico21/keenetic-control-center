//! Interface and WireGuard projections.

use core::fmt::Write as _;

use md5::{Digest as _, Md5};
use serde_json::{Map, Value, json};

use super::matching;

mod wan;

/// Synthetic encoded marker with plausible NS3 length and no recoverable secret material.
const NS3_PRESENCE: &str = "000000000000000000000000";

/// Projects configured interfaces and WireGuard peer details.
pub(super) fn interfaces(command_lines: &[Vec<String>]) -> Value {
    let mut result = Map::new();
    for words in matching(command_lines, &["interface"]) {
        let Some((name, command)) = words.split_first() else {
            continue;
        };
        let entry = result.entry(name.clone()).or_insert_with(
            || json!({"id":name,"interface-name":name,"ipcp":{"default-route":false}}),
        );
        let Some(fields) = entry.as_object_mut() else {
            continue;
        };
        wan::extend(fields, command);
        match command {
            [field, value]
                if matches!(field.as_str(), "description" | "ssid" | "security-level") =>
            {
                drop(fields.insert(field.clone(), Value::String(value.clone())));
            }
            [state] if matches!(state.as_str(), "up" | "down") => {
                drop(fields.insert("state".to_owned(), Value::String(state.clone())));
            }
            [ip, access_group, acl, direction] if ip == "ip" && access_group == "access-group" => {
                let bindings = fields
                    .entry("ip".to_owned())
                    .or_insert_with(|| json!({"access-group":[]}));
                if let Some(rows) = bindings
                    .get_mut("access-group")
                    .and_then(Value::as_array_mut)
                {
                    rows.push(json!({"acl":acl,"direction":direction}));
                }
            }
            [authentication, wpa_psk, marker]
                if authentication == "authentication"
                    && wpa_psk == "wpa-psk"
                    && marker == "ns3" =>
            {
                drop(fields.insert("authentication".to_owned(), json!({"wpa-psk":{"ns3":true}})));
            }
            [authentication, password, marker]
                if authentication == "authentication"
                    && password == "password"
                    && marker == "ns3" =>
            {
                if let Some(kind) = ["PPPoE", "L2TP", "PPTP"]
                    .into_iter()
                    .find(|kind| name.starts_with(kind))
                {
                    drop(fields.insert("type".to_owned(), Value::String(kind.to_owned())));
                }
                drop(fields.insert(
                    "authentication".to_owned(),
                    json!({"password":{"ns3":NS3_PRESENCE}}),
                ));
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
            [wireguard, obfs_key, _] if wireguard == "wireguard" && obfs_key == "obfs-key" => {
                wireguard_identity(fields, name);
                drop(fields.insert("obfs-key".to_owned(), json!({"present":true})));
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
        [field, ..] if matches!(field.as_str(), "preshared-key" | "obfs-key") => {
            drop(peer.insert(field.clone(), json!({"present":true})));
        }
        _ => {}
    }
}
