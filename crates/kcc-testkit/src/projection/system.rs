//! System configuration projections.

use serde_json::{Map, Value, json};

use super::{empty_object, matching};

/// Projects mutable system settings into the `show rc` shape.
pub(super) fn system(command_lines: &[Vec<String>]) -> Value {
    let mut fields = Map::new();
    for words in matching(command_lines, &["system"]) {
        match words {
            [field, value] if matches!(field.as_str(), "hostname" | "description") => {
                let key = if field == "hostname" { "name" } else { field };
                drop(fields.insert(key.to_owned(), Value::String(value.clone())));
            }
            [clock, timezone, locality] if clock == "clock" && timezone == "timezone" => {
                drop(fields.insert(
                    "clock".to_owned(),
                    json!({"timezone":{"locality":locality}}),
                ));
            }
            _ => {}
        }
    }
    Value::Object(fields)
}

/// Projects mutable identity settings into `show system`.
pub(super) fn system_show(command_lines: &[Vec<String>]) -> Value {
    system(command_lines)
        .as_object()
        .map_or_else(empty_object, |fields| {
            let mut shown = Map::new();
            if let Some(name) = fields.get("name") {
                drop(shown.insert("hostname".to_owned(), name.clone()));
            }
            if let Some(description) = fields.get("description") {
                drop(shown.insert("description".to_owned(), description.clone()));
            }
            Value::Object(shown)
        })
}

/// Projects the mutable locality into `show clock date`.
pub(super) fn clock_show(command_lines: &[Vec<String>]) -> Value {
    system(command_lines)
        .pointer("/clock/timezone/locality")
        .map_or_else(empty_object, |locality| json!({"tz":{"locality":locality}}))
}
