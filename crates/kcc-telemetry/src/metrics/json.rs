//! Lenient readers for router JSON: numbers may arrive as strings, lists as arrays, as
//! objects keyed by id, or wrapped in a single list-valued member.

use serde_json::Value;

/// List wrappers the router uses around row arrays.
const WRAPPERS: &[&str] = &["host", "lease", "member", "partition", "peer", "media"];

/// Rows of a list-like response: array items, a wrapped array, or the object values of a
/// map keyed by id.
pub(super) fn rows(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(map) => WRAPPERS
            .iter()
            .find_map(|key| map.get(*key).and_then(Value::as_array))
            .map_or_else(
                || map.values().filter(|row| row.is_object()).collect(),
                |items| items.iter().collect(),
            ),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Vec::new(),
    }
}

/// A numeric member, accepting numbers and numeric strings.
pub(super) fn number(value: &Value, key: &str) -> Option<f64> {
    match value.get(key)? {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse().ok(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    }
}

/// The first of `keys` that holds a number.
pub(super) fn first_number(value: &Value, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|key| number(value, key))
}

/// A non-empty string member.
pub(super) fn text<'value>(value: &'value Value, key: &str) -> Option<&'value str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

/// A boolean member, also accepting `"up"`/`"down"`, `"yes"`/`"no"` and 0/1.
pub(super) fn flag(value: &Value, key: &str) -> Option<bool> {
    match value.get(key)? {
        Value::Bool(flag) => Some(*flag),
        Value::Number(number) => number.as_u64().map(|integer| integer != 0),
        Value::String(text) => match text.as_str() {
            "up" | "yes" | "true" | "on" => Some(true),
            "down" | "no" | "false" | "off" => Some(false),
            _ => None,
        },
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// Converts a boolean to a gauge value.
pub(super) const fn gauge(flag: bool) -> f64 {
    if flag { 1.0 } else { 0.0 }
}

/// A count as a sample value, saturating at `u32::MAX` (far above any router count).
pub(super) fn count(value: u64) -> f64 {
    u32::try_from(value).map_or_else(|_| f64::from(u32::MAX), f64::from)
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use serde_json::json;

    use super::{flag, number, rows};

    /// Every list shape yields its rows; numeric strings parse.
    #[test]
    fn list_shapes_and_numeric_strings() {
        assert_eq!(rows(&json!([{"a": 1_u8}, {"a": 2_u8}])).len(), 2, "array");
        assert_eq!(rows(&json!({"host": [{"a": 1_u8}]})).len(), 1, "wrapped");
        assert_eq!(
            rows(&json!({"x": {"a": 1_u8}, "y": {"a": 2_u8}, "n": 3_u8})).len(),
            2,
            "keyed"
        );
        assert_eq!(rows(&json!(null)).len(), 0, "null");
        assert_eq!(
            number(&json!({"u": "3723"}), "u"),
            Some(3_723.0_f64),
            "string"
        );
        assert_eq!(flag(&json!({"l": "up"}), "l"), Some(true), "up");
        assert_eq!(flag(&json!({"l": "weird"}), "l"), None, "unknown");
    }
}
