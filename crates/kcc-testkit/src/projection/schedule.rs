//! Assumed schedule projection from mutable configuration.

use alloc::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::matching;

/// Projects names, descriptions and configured action times.
pub(super) fn rows(lines: &[Vec<String>]) -> Value {
    let mut rows = BTreeMap::new();
    for words in matching(lines, &["schedule"]) {
        let Some((name, tail)) = words.split_first() else {
            continue;
        };
        let row = rows.entry(name.clone()).or_insert_with(|| {
            let mut fields = Map::new();
            drop(fields.insert("name".to_owned(), json!(name)));
            drop(fields.insert("action".to_owned(), json!([])));
            fields
        });
        match tail {
            [field, text] if field == "description" => {
                drop(row.insert("description".to_owned(), json!(text)));
            }
            [field, action, minute, hour, dow] if field == "action" => {
                if let (Ok(parsed_minute), Ok(parsed_hour), Ok(parsed_dow)) =
                    (minute.parse::<u8>(), hour.parse::<u8>(), dow.parse::<u8>())
                    && let Some(actions) = row.get_mut("action").and_then(Value::as_array_mut)
                {
                    actions.push(json!({"action":action,"min":parsed_minute,"hour":parsed_hour,"dow":parsed_dow}));
                }
            }
            _ => {}
        }
    }
    Value::Array(rows.into_values().map(Value::Object).collect())
}
