//! Wire payloads for configured log destinations.

use alloc::collections::BTreeMap;

use chrono::Datelike as _;
use kcc_app::settings::SearchFlavor;
use serde_json::{Map, Value, json};
use thiserror::Error;

use super::types::LogRecord;

/// Default Elasticsearch data-stream target.
const ELASTICSEARCH_TARGET: &str = "logs-keenetic.syslog-default";
/// Default `OpenSearch` index prefix.
const OPENSEARCH_PREFIX: &str = "keenetic-logs";

/// Log payload serialization failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PayloadError {
    /// A timestamp cannot be represented as Unix nanoseconds.
    #[error("router log timestamp is outside the Unix nanosecond range")]
    Timestamp,
    /// JSON serialization failed.
    #[error("cannot serialize router log payload: {0}")]
    Json(#[from] serde_json::Error),
}

/// Encodes one Loki push request, grouping records by its bounded label set.
///
/// Loki entries carry Unix nanoseconds and no zone, so a record's naive router-local time
/// is written with the same digits as if it were UTC.
///
/// # Errors
///
/// Returns [`PayloadError`] when a timestamp or JSON value cannot be serialized.
#[inline]
pub fn loki(records: &[LogRecord]) -> Result<Vec<u8>, PayloadError> {
    let mut grouped: BTreeMap<(&str, &str), Vec<&LogRecord>> = BTreeMap::new();
    for record in records {
        grouped
            .entry((&record.router, &record.level))
            .or_default()
            .push(record);
    }
    let streams = grouped
        .into_iter()
        .map(|((router, level), mut entries)| {
            entries.sort_by_key(|record| record.ts);
            let values = entries
                .into_iter()
                .map(|record| {
                    let timestamp = record
                        .ts
                        .and_utc()
                        .timestamp_nanos_opt()
                        .ok_or(PayloadError::Timestamp)?;
                    Ok(json!([
                        timestamp.to_string(),
                        record.message,
                        metadata(record)
                    ]))
                })
                .collect::<Result<Vec<_>, PayloadError>>()?;
            Ok(json!({
                "stream": {"job": "keenetic", "router": router, "level": level},
                "values": values
            }))
        })
        .collect::<Result<Vec<_>, PayloadError>>()?;
    Ok(serde_json::to_vec(&json!({"streams": streams}))?)
}

/// Encodes alternating Bulk API create-action and ECS document lines.
///
/// # Errors
///
/// Returns [`PayloadError`] when a JSON line cannot be serialized.
#[inline]
pub fn bulk(
    records: &[LogRecord],
    flavor: SearchFlavor,
    target: Option<&str>,
) -> Result<Vec<u8>, PayloadError> {
    let mut payload = Vec::new();
    for record in records {
        let destination = target.map_or_else(|| default_target(flavor, record), ToOwned::to_owned);
        serde_json::to_writer(&mut payload, &json!({"create": {"_index": destination}}))?;
        payload.push(b'\n');
        serde_json::to_writer(&mut payload, &ecs(record))?;
        payload.push(b'\n');
    }
    Ok(payload)
}

/// Encodes one ECS-compatible JSON object per line for standard output.
///
/// # Errors
///
/// Returns [`PayloadError`] when a JSON line cannot be serialized.
#[inline]
pub fn stdout(records: &[LogRecord]) -> Result<Vec<u8>, PayloadError> {
    let mut payload = Vec::new();
    for record in records {
        serde_json::to_writer(&mut payload, &ecs(record))?;
        payload.push(b'\n');
    }
    Ok(payload)
}

/// Builds Loki structured metadata without adding unbounded stream labels.
fn metadata(record: &LogRecord) -> Value {
    let mut fields = Map::new();
    drop(fields.insert("id".to_owned(), Value::String(record.id.to_string())));
    optional(&mut fields, "label", record.label.as_deref());
    optional(&mut fields, "process", record.process.as_deref());
    optional(&mut fields, "component", record.component.as_deref());
    if let Some(pid) = record.pid {
        drop(fields.insert("pid".to_owned(), Value::String(pid.to_string())));
    }
    Value::Object(fields)
}

/// Builds an ECS document shared by Elasticsearch, `OpenSearch`, and stdout. `@timestamp` is
/// the router's naive local time, written without an offset.
fn ecs(record: &LogRecord) -> Value {
    let mut document = Map::new();
    let local = record.ts.format("%Y-%m-%dT%H:%M:%S%.f").to_string();
    drop(document.insert("@timestamp".to_owned(), json!(local)));
    drop(document.insert("message".to_owned(), json!(record.message)));
    drop(document.insert("log.level".to_owned(), json!(record.level)));
    drop(document.insert("event.id".to_owned(), json!(record.id.to_string())));
    drop(document.insert("observer.name".to_owned(), json!(record.router)));
    optional(&mut document, "log.logger", record.component.as_deref());
    optional(&mut document, "process.name", record.process.as_deref());
    if let Some(pid) = record.pid {
        drop(document.insert("process.pid".to_owned(), json!(pid)));
    }
    Value::Object(document)
}

/// Selects the flavor-specific default destination.
fn default_target(flavor: SearchFlavor, record: &LogRecord) -> String {
    match flavor {
        SearchFlavor::Opensearch => format!(
            "{OPENSEARCH_PREFIX}-{:04}.{:02}.{:02}",
            record.ts.year(),
            record.ts.month(),
            record.ts.day()
        ),
        SearchFlavor::Elasticsearch | _ => ELASTICSEARCH_TARGET.to_owned(),
    }
}

/// Inserts a present string field.
fn optional(fields: &mut Map<String, Value>, name: &str, field: Option<&str>) {
    if let Some(value) = field {
        drop(fields.insert(name.to_owned(), Value::String(value.to_owned())));
    }
}
