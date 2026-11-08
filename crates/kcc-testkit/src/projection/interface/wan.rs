//! Assumed WAN fields projected from interface CLI leaves.

use serde_json::{Map, Value, json};

use super::super::insert_path;

/// Adds fields to a configured interface without overwriting other branches.
pub(super) fn extend(fields: &mut Map<String, Value>, command: &[String]) {
    match command {
        [ip, address, dhcp] if ip == "ip" && address == "address" && dhcp == "dhcp" => {
            insert_path(fields, &["ip", "address"], json!({"dhcp":true}));
        }
        [ip, address, value, mask] if ip == "ip" && address == "address" => {
            insert_path(
                fields,
                &["ip", "address"],
                json!({"address":value,"mask":mask}),
            );
        }
        [ip, field, value] if ip == "ip" && matches!(field.as_str(), "global" | "mtu") => {
            if let Ok(number) = value.parse::<i64>() {
                insert_path(fields, &["ip", field], json!(number));
            }
        }
        [authentication, identity, value]
            if authentication == "authentication" && identity == "identity" =>
        {
            insert_path(fields, &["authentication", "identity"], json!(value));
        }
        [connect, via, value] if connect == "connect" && via == "via" => {
            insert_path(fields, &["connect", "via"], json!(value));
        }
        [ipcp, field] if ipcp == "ipcp" && field == "default-route" => {
            insert_path(fields, &["ipcp", "default-route"], json!(true));
        }
        _ => {}
    }
}
