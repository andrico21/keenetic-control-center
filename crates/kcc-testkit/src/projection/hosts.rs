//! Named account and registered-host projections.

use alloc::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::matching;

/// Projects users with password hashes only.
pub(super) fn users(command_lines: &[Vec<String>]) -> Value {
    let mut projected = BTreeMap::<String, Map<String, Value>>::new();
    for words in matching(command_lines, &["user"]) {
        let Some((name, fields)) = words.split_first() else {
            continue;
        };
        let user = projected.entry(name.clone()).or_insert_with(|| {
            let mut initial = Map::new();
            drop(initial.insert("name".to_owned(), Value::String(name.clone())));
            initial
        });
        match fields {
            [tag, value] if tag == "tag" => push_string(user, "tag", value),
            [password, format, digest]
                if password == "password" && matches!(format.as_str(), "md5" | "nt") =>
            {
                drop(user.insert("password".to_owned(), json!({format:digest})));
            }
            _ => {}
        }
    }
    Value::Array(projected.into_values().map(Value::Object).collect())
}

/// Projects registered hosts and hotspot overrides.
pub(super) fn hotspot(command_lines: &[Vec<String>], fixture: Option<&Value>) -> Value {
    let mut rows = fixture
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let registered = matching(command_lines, &["known", "host"])
        .filter_map(|words| match words {
            [name, mac] => Some((mac.clone(), name.clone())),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    for (mac, name) in registered {
        let mut row = json!({"mac":mac,"name":name,"registered":true});
        if let Some(fields) = row.as_object_mut() {
            for command in matching(command_lines, &["ip", "hotspot", "host", &mac]) {
                match command {
                    [access] if matches!(access.as_str(), "permit" | "deny") => {
                        drop(fields.insert("access".to_owned(), Value::String(access.clone())));
                    }
                    [field, value] if matches!(field.as_str(), "policy" | "schedule") => {
                        drop(fields.insert(field.clone(), Value::String(value.clone())));
                    }
                    _ => {}
                }
            }
        }
        rows.retain(|candidate| candidate.get("mac").and_then(Value::as_str) != Some(&mac));
        rows.push(row);
    }
    Value::Array(rows)
}

/// Adds a string to an array field.
fn push_string(fields: &mut Map<String, Value>, key: &str, value: &str) {
    let entry = fields
        .entry(key.to_owned())
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Value::Array(items) = entry {
        items.push(Value::String(value.to_owned()));
    }
}
