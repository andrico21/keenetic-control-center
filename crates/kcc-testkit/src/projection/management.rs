//! Assumed running-configuration projections for management listeners.

use serde_json::{Map, Value, json};

use super::{insert_path, matching};

/// Adds listener settings without replacing other IP configuration branches.
pub(super) fn extend(root: &mut Map<String, Value>, lines: &[Vec<String>]) {
    for field in ["enable", "redirect"] {
        insert_path(root, &["ip", "http", "ssl", field], json!(false));
    }
    for listener in ["http", "ssh", "telnet"] {
        for words in matching(lines, &["ip", listener]) {
            match words {
                [field, value] if field == "port" => {
                    if let Ok(port) = value.parse::<u16>() {
                        insert_path(root, &["ip", listener, "port"], json!(port));
                    }
                }
                [field, value] if field == "security-level" => {
                    insert_path(root, &["ip", listener, "security-level"], json!(value));
                }
                [ssl, field] if ssl == "ssl" && matches!(field.as_str(), "enable" | "redirect") => {
                    insert_path(root, &["ip", listener, "ssl", field], json!(true));
                }
                [ssl, field, value] if ssl == "ssl" && field == "port" => {
                    if let Ok(port) = value.parse::<u16>() {
                        insert_path(root, &["ip", listener, "ssl", "port"], json!(port));
                    }
                }
                _ => {}
            }
        }
    }
}
