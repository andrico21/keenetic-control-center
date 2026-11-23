//! The read-only probe: the router facts the Entware code relies on, recorded as the
//! router reports them, plus `kcc entware status`.

use kcc_rci::{RciBody, RciClient, RciError, RciPath};
use serde_json::{Map, Value, json};

use super::{
    Reach, TestResult,
    admit::admit,
    contract::{self, Read, skip},
    evidence,
};

/// One read, or why it failed.
type Reading = Result<Value, String>;

/// Runs the probe: the gate, the reads, the anonymized capture.
// NOT cancel-safe: a sign-in dropped mid-way can leave an orphaned router session; reads only.
pub(crate) async fn run(read: Read<'_>, reach: &Reach) -> TestResult {
    let base = match contract::base(read) {
        Ok(base) => base,
        Err(reason) => {
            skip(reason);
            return Ok(());
        }
    };
    let admitted = admit(&base, reach.allow_loopback).await?;
    let client = &admitted.connection.client;
    let log_path = RciPath::from_segments(["show", "log"])?;
    let capture = json!({
        "media": media(show(client, &["show", "media"]).await),
        "components": components(show(client, &["show", "components", "list"]).await),
        "rc_opkg": rc_opkg(client).await,
        "version": version(show(client, &["show", "version"]).await),
        "log": log_shape(client.post(&log_path, &json!({"max-lines": 1_u32})).await),
        "status": admitted
            .home
            .json(&["entware", "status"])
            .unwrap_or_else(|error| json!({"error": error.to_string()})),
    });
    drop(evidence::write(&reach.evidence, evidence::PROBE, &capture)?);
    Ok(())
}

/// One `show` read as JSON.
// NOT cancel-safe: it may sign in first; a read.
pub(crate) async fn show(client: &RciClient, segments: &[&str]) -> Reading {
    let path =
        RciPath::from_segments(segments.iter().copied()).map_err(|error| error.to_string())?;
    match client.show(&path, &()).await {
        Ok(RciBody::Json(response)) => Ok(response.value),
        Ok(RciBody::Text(text)) => Err(format!("text reply of {} bytes", text.len())),
        Ok(_) => Err("unknown reply kind".to_owned()),
        Err(error) => Err(error.to_string()),
    }
}

/// The objects of a list reply: array items, or an object's object members (keyed), or
/// the items of the arrays it holds.
pub(crate) fn entries(value: &Value) -> Vec<(String, &Map<String, Value>)> {
    match value {
        Value::Array(items) => items
            .iter()
            .enumerate()
            .filter_map(|(index, item)| item.as_object().map(|object| (index.to_string(), object)))
            .collect(),
        Value::Object(fields) => fields
            .iter()
            .flat_map(|(key, field)| match field {
                Value::Object(object) => vec![(key.clone(), object)],
                Value::Array(_) => entries(field),
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Vec::new(),
            })
            .collect(),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Vec::new(),
    }
}

/// The JSON type of `value`.
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

/// The member names of `object`, sorted.
fn keys(object: &Map<String, Value>) -> Vec<&str> {
    object.keys().map(String::as_str).collect()
}

/// `name` or `id` of an entry, else its key.
fn name(key: &str, entry: &Map<String, Value>) -> Value {
    entry
        .get("name")
        .or_else(|| entry.get("id"))
        .cloned()
        .unwrap_or_else(|| Value::from(key))
}

/// The media: label, uuid presence, `initialize-supported` and filesystem per medium.
fn media(reading: Reading) -> Value {
    reading.map_or_else(
        |error| json!({"error": error}),
        |value| {
            let media = entries(&value)
                .into_iter()
                .map(|(key, entry)| {
                    json!({
                        "id": name(&key, entry),
                        "keys": keys(entry),
                        "label": entry.get("label"),
                        "uuid_present": entry.contains_key("uuid"),
                        "initialize_supported": entry.get("initialize-supported"),
                        "filesystem": entry.get("filesystem").or_else(|| entry.get("fstype")),
                    })
                })
                .collect::<Vec<_>>();
            json!({"shape": kind(&value), "entries": media})
        },
    )
}

/// The listed components, whether `opkg` and `ext` are among them and whether components
/// that are not installed are listed.
fn components(reading: Reading) -> Value {
    reading.map_or_else(
        |error| json!({"error": error}),
        |value| {
            let listed = entries(&value)
                .into_iter()
                .map(|(key, entry)| json!({"name": name(&key, entry), "installed": entry.get("installed")}))
                .collect::<Vec<_>>();
            let has = |wanted: &str| {
                listed
                    .iter()
                    .any(|entry| entry.get("name").and_then(Value::as_str) == Some(wanted))
            };
            let not_installed = listed
                .iter()
                .any(|entry| entry.get("installed") == Some(&Value::Bool(false)));
            json!({
                "shape": kind(&value),
                "opkg_listed": has("opkg"),
                "ext_listed": has("ext"),
                "not_installed_listed": not_installed,
                "components": listed,
            })
        },
    )
}

/// The `opkg` subtree of the running configuration.
// NOT cancel-safe: it may sign in first; a read.
async fn rc_opkg(client: &RciClient) -> Value {
    match client.show_rc(json!({"opkg": {}})).await {
        Ok(answer) => answer
            .configuration_tree()
            .get("opkg")
            .cloned()
            .unwrap_or(Value::Null),
        Err(error) => json!({"error": error.to_string()}),
    }
}

/// The architecture and model of `show version`.
fn version(reading: Reading) -> Value {
    reading.map_or_else(
        |error| json!({"error": error}),
        |value| {
            json!({
                "arch": value.get("arch"),
                "hw_id": value.get("hw_id"),
                "title": value.get("title"),
            })
        },
    )
}

/// The shape of a `show log` reply: its kind, member names and entry layout, no record.
pub(crate) fn log_shape(reply: Result<RciBody, RciError>) -> Value {
    match reply {
        Ok(RciBody::Json(response)) => {
            let value = response.value;
            let log = value.get("log").map_or_else(
                || json!({"type": "absent"}),
                |log| {
                    let listed = entries(log);
                    let first = listed.first().map(|(_key, entry)| {
                        let nested = entry
                            .iter()
                            .filter_map(|(field, inner)| {
                                inner
                                    .as_object()
                                    .map(|object| (field.clone(), json!(keys(object))))
                            })
                            .collect::<Map<_, _>>();
                        json!({"keys": keys(entry), "nested": nested})
                    });
                    json!({"type": kind(log), "entries": listed.len(), "first": first})
                },
            );
            let top = value.as_object().map(keys);
            json!({"kind": "json", "top_keys": top, "continued": value.get("continued"), "log": log})
        }
        Ok(RciBody::Text(text)) => json!({
            "kind": "text",
            "bytes": text.len(),
            "lines": text.lines().count(),
            "opkg_manager": text.contains("Opkg::Manager"),
        }),
        Ok(_) => json!({"kind": "unknown"}),
        Err(error) => json!({"kind": "error", "error": error.to_string()}),
    }
}
