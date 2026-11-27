//! The sanitized request log: one record per request, with every root parser line on it.

use axum::extract::Request;
use serde_json::Value;

use super::{Shared, lock};
use crate::RequestRecord;

/// Command fields whose value is a secret; a parser line holding one is logged as `None`.
const SECRET_MARKERS: [&str; 7] = [
    " password ",
    "private-key",
    "preshared-key",
    "wpa-psk",
    "xauth-password",
    "obfs-key",
    "ike key",
];

/// Position of a request's record in the log, carried as a request extension so the
/// handler attaches parser lines to its own request even when requests overlap.
#[derive(Clone, Copy, Debug)]
pub(super) struct RecordIndex(usize);

/// Logs method, path and sorted query pairs of `request`, never headers or bodies.
pub(super) fn push(shared: &Shared, request: &Request) -> RecordIndex {
    let mut query: Vec<(String, String)> = request
        .uri()
        .query()
        .into_iter()
        .flat_map(|value| value.split('&'))
        .map(|pair| {
            pair.split_once('=').map_or_else(
                || (pair.to_owned(), String::new()),
                |(key, value)| (key.to_owned(), value.to_owned()),
            )
        })
        .collect();
    query.sort();
    let index = {
        let mut log = lock(&shared.request_log);
        log.push(RequestRecord {
            method: request.method().clone(),
            path: request.uri().path().to_owned(),
            query,
            commands: Vec::new(),
        });
        log.len().saturating_sub(1)
    };
    let _previous: usize = shared.logged.send_replace(index.saturating_add(1));
    RecordIndex(index)
}

/// Attaches every root `parse` line of `body` (one object or a batch array) to the record
/// at `index` in body order, each secret-bearing line as `None`.
pub(super) fn record_commands(shared: &Shared, RecordIndex(index): RecordIndex, body: &Value) {
    let items = body
        .as_array()
        .map_or_else(|| vec![body], |items| items.iter().collect());
    let lines = items
        .into_iter()
        .filter_map(|item| item.get("parse").and_then(Value::as_str))
        .map(|line| {
            let secret = SECRET_MARKERS.iter().any(|marker| line.contains(marker));
            (!secret).then(|| line.to_owned())
        });
    if let Some(record) = lock(&shared.request_log).get_mut(index) {
        record.commands.extend(lines);
    }
}

/// Attaches to the record at `index` what a background tool was asked to do.
///
/// The line is the path's words, then `<key> <value>` for each scalar member of `body` in
/// key order (`tools ping count 2 host <address>`); one with a secret-bearing field is
/// logged as `None`.
pub(super) fn record_tool(
    shared: &Shared,
    RecordIndex(index): RecordIndex,
    path: &str,
    body: &Value,
) {
    let mut line = path.replace('/', " ");
    for (key, member) in body.as_object().into_iter().flatten() {
        let text = match member {
            Value::String(text) => text.clone(),
            Value::Number(number) => number.to_string(),
            Value::Bool(flag) => flag.to_string(),
            Value::Null | Value::Array(_) | Value::Object(_) => continue,
        };
        line.push(' ');
        line.push_str(key);
        line.push(' ');
        line.push_str(&text);
    }
    let secret = SECRET_MARKERS.iter().any(|marker| line.contains(marker));
    if let Some(record) = lock(&shared.request_log).get_mut(index) {
        record.commands.push((!secret).then_some(line));
    }
}
