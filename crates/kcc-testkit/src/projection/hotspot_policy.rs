//! Assumed hotspot configuration policy projection.

use serde_json::{Map, Value, json};

use super::matching;

/// Projects the configured default and interface policies without host data.
pub(super) fn project(lines: &[Vec<String>]) -> Value {
    let mut result = Map::new();
    let mut interfaces = Map::new();
    for words in matching(lines, &["ip", "hotspot"]) {
        match words {
            [field, selection] if field == "default-policy" => {
                drop(result.insert("default-policy".to_owned(), json!(selection)));
            }
            [field, interface, selection] if field == "policy" => {
                drop(interfaces.insert(interface.clone(), json!(selection)));
            }
            _ => {}
        }
    }
    drop(result.insert("policy".to_owned(), Value::Object(interfaces)));
    Value::Object(result)
}
