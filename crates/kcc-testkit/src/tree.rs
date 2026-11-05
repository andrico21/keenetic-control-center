//! Operations on the in-memory JSON settings tree and on show fixtures.
//!
//! Nodes are addressed by JSON pointers resolved from an RCI path plus an optional
//! `name`/`mac` query selector. Writes mirror the request shape: each applied leaf
//! answers a `status` array, and fields the tree does not know are dropped from the
//! answer, so a body made only of unknown fields answers `{}` like the real router.

use serde_json::{Map, Value, json};

/// Pointers whose objects are named collections: posting a new key creates an entry.
const COLLECTIONS: [&str; 1] = ["/interface"];

/// Query keys that select a collection entry or an array member.
const SELECTOR_KEYS: [&str; 2] = ["name", "mac"];

/// A `name=..` or `mac=..` selector taken from the query string or a request body.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Selector<'query> {
    /// `name` or `mac`.
    key: &'query str,
    /// The value to match.
    value: &'query str,
}

/// The first selector found among `pairs`, `name` preferred over `mac`.
pub(crate) fn selector<'pairs>(pairs: &[(&'pairs str, &'pairs str)]) -> Option<Selector<'pairs>> {
    SELECTOR_KEYS.into_iter().find_map(|wanted| {
        pairs
            .iter()
            .find(|&&(key, _)| key == wanted)
            .map(|&(key, value)| Selector { key, value })
    })
}

impl Selector<'_> {
    /// Whether an array member carries this selector's value.
    fn matches(self, member: &Value) -> bool {
        member.get(self.key).and_then(Value::as_str) == Some(self.value)
    }
}

/// Where a path and selector landed in a tree: the node's JSON pointer, and the
/// collection key the selector consumed as the final step, if any.
pub(crate) type Resolved = (String, Option<String>);

/// Escapes one JSON pointer token.
fn escape(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Undoes [`escape`].
fn unescape(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

/// Steps the selector into `node` if it can be consumed there and `next` is not a key.
fn consume<'tree>(
    node: &'tree Value,
    pointer: &mut String,
    selector: &mut Option<Selector<'_>>,
    next: Option<&str>,
) -> Option<(&'tree Value, Option<String>)> {
    let wanted = (*selector)?;
    if let Some(items) = node.as_array() {
        let index = items.iter().position(|member| wanted.matches(member))?;
        *selector = None;
        pointer.push('/');
        pointer.push_str(&index.to_string());
        return items.get(index).map(|member| (member, None));
    }
    let map = node.as_object()?;
    if next.is_some_and(|key| map.contains_key(key)) || wanted.key != "name" {
        return None;
    }
    let child = map.get(wanted.value)?;
    *selector = None;
    pointer.push('/');
    pointer.push_str(&escape(wanted.value));
    Some((child, Some(wanted.value.to_owned())))
}

/// Resolves `segments` under `root`, consuming `selector` where it fits.
///
/// `None` when a segment is missing or the selector matched nothing.
pub(crate) fn resolve(
    root: &Value,
    segments: &[&str],
    selector: Option<Selector<'_>>,
) -> Option<Resolved> {
    let mut pending = selector;
    let mut node = root;
    let mut pointer = String::new();
    let mut wrap = None;
    for segment in segments {
        if let Some((child, _)) = consume(node, &mut pointer, &mut pending, Some(segment)) {
            node = child;
        }
        node = node.get(*segment)?;
        pointer.push('/');
        pointer.push_str(&escape(segment));
    }
    if pending.is_some() {
        let (_, key) = consume(node, &mut pointer, &mut pending, None)?;
        wrap = key;
    }
    Some((pointer, wrap))
}

/// Reads a settings node; a collection entry picked by `name` comes back keyed by it.
pub(crate) fn get(
    root: &Value,
    segments: &[&str],
    selector: Option<Selector<'_>>,
) -> Option<Value> {
    let (pointer, wrap) = resolve(root, segments, selector)?;
    let node = root.pointer(&pointer)?.clone();
    Some(match wrap {
        Some(key) => {
            let mut map = Map::new();
            drop(map.insert(key, node));
            Value::Object(map)
        }
        None => node,
    })
}

/// Reads a show fixture, narrowed by `selector` when one is given.
pub(crate) fn select_show(fixture: &Value, selector: Option<Selector<'_>>) -> Option<Value> {
    let Some(wanted) = selector else {
        return Some(fixture.clone());
    };
    if let Some(items) = fixture.as_array() {
        return items.iter().find(|member| wanted.matches(member)).cloned();
    }
    fixture.as_object()?.get(wanted.value).cloned()
}

/// A one-entry `status` array.
fn status_entries(level: &str, message: &str) -> Value {
    json!([{
        "status": level,
        "code": "0",
        "ident": "FakeRouter",
        "message": message,
    }])
}

/// A one-entry `status` array wrapped in an object.
pub(crate) fn status(level: &str, message: &str) -> Value {
    json!({ "status": status_entries(level, message) })
}

/// The string-valued fields of `fields` as `(key, value)` pairs.
pub(crate) fn string_pairs(fields: &Map<String, Value>) -> Vec<(&str, &str)> {
    fields
        .iter()
        .filter_map(|(key, value)| value.as_str().map(|text| (key.as_str(), text)))
        .collect()
}

/// Whether `value` is an object carrying `"no": true`.
fn is_no(value: &Value) -> bool {
    value.get("no") == Some(&Value::Bool(true))
}

/// Whether `value` is `{}`.
fn is_empty_object(value: &Value) -> bool {
    value.as_object().is_some_and(Map::is_empty)
}

/// Removes the node at `pointer`; `false` when it does not exist or is the root.
pub(crate) fn remove(root: &mut Value, pointer: &str) -> bool {
    let Some((parent_pointer, token)) = pointer.rsplit_once('/') else {
        return false;
    };
    let key = unescape(token);
    match root.pointer_mut(parent_pointer) {
        Some(Value::Object(map)) => map.remove(&key).is_some(),
        Some(Value::Array(items)) => match key.parse::<usize>() {
            Ok(index) if index < items.len() => {
                drop(items.remove(index));
                true
            }
            Ok(_) | Err(_) => false,
        },
        Some(Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)) | None => false,
    }
}

/// Applies one array-member body (identified by `name` or `mac`) to `items`.
fn apply_member(items: &mut Vec<Value>, fields: &Map<String, Value>, pointer: &str) -> Value {
    let body = Value::Object(fields.clone());
    let identity = selector(&string_pairs(fields));
    if is_no(&body) {
        let before = items.len();
        match identity {
            Some(wanted) => items.retain(|member| !wanted.matches(member)),
            None => items.clear(),
        }
        return if items.len() < before {
            status("message", "removed.")
        } else {
            status("error", "not found.")
        };
    }
    let existing =
        identity.and_then(|wanted| items.iter_mut().find(|member| wanted.matches(member)));
    if let Some(member) = existing {
        return apply(member, &body, &format!("{pointer}/-"));
    }
    items.push(body);
    status("message", "created.")
}

/// Applies object `fields` to `map` at `pointer`, returning the mirrored answer.
fn apply_fields(map: &mut Map<String, Value>, fields: &Map<String, Value>, pointer: &str) -> Value {
    let collection = COLLECTIONS.contains(&pointer);
    let mut answer = Map::new();
    for (key, value) in fields {
        if key == "no" {
            continue;
        }
        let child_pointer = format!("{pointer}/{}", escape(key));
        if is_no(value) && map.get(key).is_some_and(|child| !child.is_array()) {
            drop(map.remove(key));
            drop(answer.insert(key.clone(), status("message", "removed.")));
        } else if let Some(child) = map.get_mut(key) {
            let reply = apply(child, value, &child_pointer);
            if !is_empty_object(&reply) {
                drop(answer.insert(key.clone(), reply));
            }
        } else if collection && key == "name" {
            if let Some(name) = value.as_str() {
                let _: &mut Value = map
                    .entry(name.to_owned())
                    .or_insert_with(|| Value::Object(Map::new()));
                drop(answer.insert(name.to_owned(), status("message", "created.")));
            }
        } else if collection && value.is_object() && !is_no(value) {
            let mut created = Value::Object(Map::new());
            let mut reply = apply(&mut created, value, &child_pointer);
            drop(map.insert(key.clone(), created));
            if let Some(reply_map) = reply.as_object_mut() {
                drop(reply_map.insert("status".to_owned(), status_entries("message", "created.")));
            }
            drop(answer.insert(key.clone(), reply));
        } else {
            // Unknown field: the real router ignores it and says nothing.
        }
    }
    Value::Object(answer)
}

/// Applies `body` to `node` at `pointer`, returning the mirrored answer.
pub(crate) fn apply(node: &mut Value, body: &Value, pointer: &str) -> Value {
    match (node, body) {
        (Value::Array(items), Value::Object(fields)) => apply_member(items, fields, pointer),
        (Value::Array(items), Value::Array(bodies)) => Value::Array(
            bodies
                .iter()
                .map(|member| {
                    member.as_object().map_or_else(
                        || Value::Object(Map::new()),
                        |fields| apply_member(items, fields, pointer),
                    )
                })
                .collect(),
        ),
        (Value::Object(map), Value::Object(fields)) => apply_fields(map, fields, pointer),
        (
            target @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)),
            value @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)),
        ) => {
            value.clone_into(target);
            status("message", "saved.")
        }
        (_, _) => Value::Object(Map::new()),
    }
}

/// `show rc` / `show sc`: fills the request shape with values from `tree`.
pub(crate) fn read_through(tree: &Value, request: &Value) -> Value {
    match request.as_object() {
        Some(fields) if !fields.is_empty() => {
            let mut answer = Map::new();
            for (key, sub) in fields {
                if let Some(child) = tree.get(key) {
                    drop(answer.insert(key.clone(), read_through(child, sub)));
                }
            }
            Value::Object(answer)
        }
        Some(_) | None => tree.clone(),
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use serde_json::json;

    use super::{apply, get, read_through, remove, resolve, selector};

    /// A `name` selector on a collection wraps the entry under its key.
    #[test]
    fn get_named_entry() {
        let tree = json!({"interface": {"Bridge1": {"traffic-shape": {"rate": "5"}}}});
        let bridge = selector(&[("name", "Bridge1")]);
        assert_eq!(
            get(&tree, &["interface"], bridge),
            Some(json!({"Bridge1": {"traffic-shape": {"rate": "5"}}}))
        );
        assert_eq!(
            get(&tree, &["interface", "traffic-shape"], bridge),
            Some(json!({"rate": "5"}))
        );
        assert_eq!(
            get(&tree, &["interface"], selector(&[("name", "Nope")])),
            None
        );
    }

    /// A `mac` selector picks an array member mid-path.
    #[test]
    fn mac_selector_in_array() {
        let tree = json!({"host": [{"mac": "02:00:00:00:00:01", "policy": "P0"}]});
        let host = selector(&[("mac", "02:00:00:00:00:01")]);
        let resolved = resolve(&tree, &["host", "policy"], host);
        assert_eq!(
            resolved.map(|(pointer, _)| pointer),
            Some("/host/0/policy".to_owned())
        );
    }

    /// Unknown fields answer `{}` and change nothing.
    #[test]
    fn unknown_field_is_silent() {
        let mut tree = json!({"system": {"name": "a"}});
        let before = tree.clone();
        let reply = apply(&mut tree, &json!({"system": {"bogus": "x"}}), "");
        assert_eq!(reply, json!({}));
        assert_eq!(tree, before);
    }

    /// `"no": true` removes the addressed child and array members.
    #[test]
    fn no_deletes() {
        let mut tree = json!({"ip": {"nat": [{"interface": "A"}], "x": {"y": 1_i32}}});
        let reply = apply(&mut tree, &json!({"ip": {"x": {"no": true}}}), "");
        assert!(reply.pointer("/ip/x/status").is_some(), "{reply}");
        let cleared = apply(&mut tree, &json!({"ip": {"nat": {"no": true}}}), "");
        assert!(cleared.pointer("/ip/nat/status").is_some(), "{cleared}");
        assert_eq!(tree, json!({"ip": {"nat": []}}));
        assert!(remove(&mut tree, "/ip/nat"));
        assert_eq!(tree, json!({"ip": {}}));
    }

    /// Posting a new key into a collection creates the entry.
    #[test]
    fn collection_create() {
        let mut tree = json!({"interface": {}});
        let reply = apply(&mut tree, &json!({"interface": {"PPTP0": {}}}), "");
        assert!(
            reply.pointer("/interface/PPTP0/status").is_some(),
            "{reply}"
        );
        assert!(tree.pointer("/interface/PPTP0").is_some(), "{tree}");
    }

    /// `show rc` fills the requested shape.
    #[test]
    fn read_through_shape() {
        let tree = json!({"interface": {"Bridge1": {"description": "G", "up": true}}});
        assert_eq!(
            read_through(
                &tree,
                &json!({"interface": {"Bridge1": {"description": {}}}})
            ),
            json!({"interface": {"Bridge1": {"description": "G"}}})
        );
    }
}
