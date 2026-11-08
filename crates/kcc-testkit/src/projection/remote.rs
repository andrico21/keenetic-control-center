//! Assumed cloud and proxy running-configuration projections.

use serde_json::{Map, Value, json};

use super::{insert_path, matching};

/// Projects mutable cloud exposure, booked names and HTTP proxies.
pub(super) fn extend(root: &mut Map<String, Value>, lines: &[Vec<String>]) {
    for words in matching(lines, &["cloud", "control2", "security-level"]) {
        if let [level] = words {
            insert_path(root, &["cloud", "control2", "security-level"], json!(level));
        }
    }
    let mut names = Vec::new();
    for words in matching(lines, &["ndns", "book-name"]) {
        if let [name, domain] = words {
            names.push(json!({"name":name,"domain":domain}));
        }
    }
    insert_path(root, &["ndns", "book-name"], Value::Array(names));
    insert_path(root, &["ip", "http", "proxy"], json!({}));
    for words in matching(lines, &["ip", "http", "proxy"]) {
        match words {
            [name] => insert_path(root, &["ip", "http", "proxy", name], json!({})),
            [name, upstream, protocol, host, port] if upstream == "upstream" => {
                if let Ok(number) = port.parse::<u16>() {
                    insert_path(
                        root,
                        &["ip", "http", "proxy", name, "upstream"],
                        json!({"protocol":protocol,"host":host,"port":number}),
                    );
                }
            }
            _ => {}
        }
    }
}
