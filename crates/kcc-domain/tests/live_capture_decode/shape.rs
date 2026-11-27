//! JSON shape comparison: paths and kinds, never values.

use alloc::collections::BTreeSet;

use serde_json::Value;

/// The kind name of a JSON value.
const fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// A map key as a path segment: kept when it looks like a field name
/// (`^[A-Za-z][A-Za-z0-9_-]{0,63}$`), else `*`.
fn segment(key: &str) -> &str {
    let mut characters = key.chars();
    let field = key.len() <= 64
        && characters
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic())
        && characters.all(|rest| rest.is_ascii_alphanumeric() || matches!(rest, '_' | '-'));
    if field { key } else { "*" }
}

/// Every path of `value` with its kind; array elements share the path `[]`, so array
/// lengths do not matter.
pub(crate) fn shape(value: &Value) -> BTreeSet<(String, &'static str)> {
    let mut found = BTreeSet::new();
    walk(value, "$".to_owned(), &mut found);
    found
}

/// Adds `value` at `path` and everything below it to `found`.
fn walk(value: &Value, path: String, found: &mut BTreeSet<(String, &'static str)>) {
    match value {
        Value::Object(fields) => {
            for (key, inner) in fields {
                walk(inner, format!("{path}.{}", segment(key)), found);
            }
        }
        Value::Array(elements) => {
            for inner in elements {
                walk(inner, format!("{path}[]"), found);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    let _new: bool = found.insert((path, kind(value)));
}

/// The paths with kinds that only one of `fixture` and `captured` has, each line naming a
/// path, a kind and the side; no value appears.
pub(crate) fn differences(fixture: &Value, captured: &Value) -> Vec<String> {
    let expected = shape(fixture);
    let actual = shape(captured);
    let only_fixture = expected
        .difference(&actual)
        .map(|(path, kind)| format!("{path} ({kind}) only in the fixture"));
    let only_capture = actual
        .difference(&expected)
        .map(|(path, kind)| format!("{path} ({kind}) only in the capture"));
    only_fixture.chain(only_capture).collect()
}
