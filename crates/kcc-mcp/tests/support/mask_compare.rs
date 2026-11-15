//! Comparison helpers for the masker superset test: distinct corpus values and the
//! places a masker replaced.

use alloc::collections::BTreeSet;

use kcc_config::config_text::{Node, Token};
use serde_json::Value;

/// What every masker writes in this comparison; no corpus value equals it.
pub(crate) const MARKER: &str = "<marker>";

/// `value` with every scalar replaced by a distinct string, so a masked scalar always
/// differs from its original.
pub(crate) fn distinct_leaves(value: &mut Value, next: &mut usize) {
    match value {
        Value::Object(object) => object
            .values_mut()
            .for_each(|member| distinct_leaves(member, next)),
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| distinct_leaves(item, next)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            *next = next.saturating_add(1);
            *value = Value::String(format!("leaf-{next}"));
        }
    }
}

/// The JSON pointers whose member `masker` replaced with [`MARKER`].
pub(crate) fn masked(original: &Value, masker: impl Fn(&mut Value, &str)) -> BTreeSet<String> {
    let mut copy = original.clone();
    masker(&mut copy, MARKER);
    let mut found = BTreeSet::new();
    collect(original, &copy, String::new(), &mut found);
    found
}

/// Records each place where `masked` holds the marker and `original` does not.
fn collect(original: &Value, masked: &Value, at: String, found: &mut BTreeSet<String>) {
    match (original, masked) {
        (Value::Object(before), Value::Object(after)) => {
            for (name, member) in before {
                if let Some(shown) = after.get(name) {
                    let escaped = name.replace('~', "~0").replace('/', "~1");
                    collect(member, shown, format!("{at}/{escaped}"), found);
                }
            }
        }
        (Value::Array(before), Value::Array(after)) => {
            for (index, (member, shown)) in before.iter().zip(after).enumerate() {
                collect(member, shown, format!("{at}/{index}"), found);
            }
        }
        (_, Value::String(shown)) if shown == MARKER && original != masked => {
            let _: bool = found.insert(at);
        }
        _ => {}
    }
}

/// Asserts that every pointer in `old` is in `new` or below one of its pointers.
///
/// # Panics
///
/// Panics naming the first pointer `label`'s masker masked and the shared one did not.
pub(crate) fn covers(new: &BTreeSet<String>, old: &BTreeSet<String>, label: &str) {
    for pointer in old {
        assert!(
            new.iter()
                .any(|shared| pointer == shared || pointer.starts_with(&format!("{shared}/"))),
            "{label} masked {pointer}, the shared masker does not"
        );
    }
}

/// Replaces every `ns3` payload below `nodes` with a distinct blob.
pub(crate) fn distinct_blobs(nodes: &mut [Node], next: &mut usize) {
    for node in nodes {
        for token in &mut node.tokens {
            if let Token::Ns3(blob) = token {
                *next = next.saturating_add(1);
                *blob = format!("blob{next}");
            }
        }
        distinct_blobs(&mut node.children, next);
    }
}
