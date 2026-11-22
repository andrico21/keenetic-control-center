//! Router log wire-format parsing.

use std::time::SystemTime;

use chrono::{DateTime, Datelike as _, NaiveDate, NaiveDateTime, TimeDelta, Utc};
use serde_json::Value;
use thiserror::Error;

use super::types::LogRecord;

/// A malformed router log response or record.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The response has no object-valued `log` member.
    #[error("router log response is malformed")]
    Response,
    /// A record has no usable message text.
    #[error("router log record message is malformed")]
    Message,
    /// A timestamp is absent or malformed.
    #[error("router log record timestamp is malformed")]
    Timestamp,
}

/// The records of one router response.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ParsedLog {
    /// Every entry keyed by a record id, in ascending id order; `None` marks a record whose
    /// message or timestamp is malformed.
    pub entries: Vec<(u64, Option<LogRecord>)>,
    /// Entries skipped because their key is not a record id.
    pub unnumbered: usize,
}

/// Parses every record in one router response in ascending id order.
///
/// A malformed record is marked and skipped, never fatal. `now` is kcc's own UTC wall
/// clock; it only places a bracket timestamp, which has no year, in the right year.
///
/// # Errors
///
/// Returns [`ParseError::Response`] when the response has no object-valued `log` member.
#[inline]
pub fn parse_records(
    router: &str,
    response: &Value,
    now: NaiveDateTime,
) -> Result<ParsedLog, ParseError> {
    let entries = response
        .get("log")
        .and_then(Value::as_object)
        .ok_or(ParseError::Response)?;
    let mut parsed = ParsedLog::default();
    for (text_id, value) in entries {
        if let Ok(id) = text_id.parse::<u64>() {
            let record = parse_record(router, id, value, now).ok();
            parsed.entries.push((id, record));
        } else {
            parsed.unnumbered = parsed.unnumbered.saturating_add(1);
        }
    }
    parsed.entries.sort_by_key(|(id, _)| *id);
    Ok(parsed)
}

/// Parses every record in one router response like [`parse_records`], placing bracket
/// timestamps with kcc's own UTC wall clock read now.
///
/// # Errors
///
/// Returns [`ParseError::Response`] when the response has no object-valued `log` member.
#[inline]
pub fn parse_records_now(router: &str, response: &Value) -> Result<ParsedLog, ParseError> {
    let utc: DateTime<Utc> = SystemTime::now().into();
    parse_records(router, response, utc.naive_utc())
}

/// Parses one router record and merges newline continuations into its message.
///
/// # Errors
///
/// Returns [`ParseError`] when mandatory record fields are malformed.
fn parse_record(
    router: &str,
    id: u64,
    value: &Value,
    now: NaiveDateTime,
) -> Result<LogRecord, ParseError> {
    let body = value.get("message").unwrap_or(value);
    let raw = body
        .get("message")
        .and_then(Value::as_str)
        .ok_or(ParseError::Message)?;
    let (ts, text) = timestamp(value, raw, now)?;
    let merged = text.lines().map(str::trim).collect::<Vec<_>>().join("\n");
    let (process, pid, component, message) = prefixes(&merged);
    let label = body.get("label").and_then(Value::as_str).map(str::to_owned);
    let level = body
        .get("level")
        .and_then(Value::as_str)
        .map_or_else(|| level_from_label(label.as_deref()), normalize_level);
    Ok(LogRecord {
        router: router.to_owned(),
        id,
        ts,
        level,
        label,
        process,
        pid,
        component,
        message,
    })
}

/// Selects an explicit timestamp (its local time) or parses the conventional bracket prefix.
///
/// # Errors
///
/// Returns [`ParseError::Timestamp`] when neither timestamp representation is usable.
fn timestamp<'text>(
    value: &Value,
    raw: &'text str,
    now: NaiveDateTime,
) -> Result<(NaiveDateTime, &'text str), ParseError> {
    if let Some(text) = value.get("time").and_then(Value::as_str) {
        let parsed = DateTime::parse_from_rfc3339(text).map_err(|_error| ParseError::Timestamp)?;
        return Ok((parsed.naive_local(), raw));
    }
    let (prefix, rest) = raw
        .strip_prefix('[')
        .and_then(|text| text.split_once("] "))
        .ok_or(ParseError::Timestamp)?;
    let parts: Vec<&str> = prefix.split_ascii_whitespace().collect();
    let [month_name, day_text, clock] = parts.as_slice() else {
        return Err(ParseError::Timestamp);
    };
    let month = month_number(month_name).ok_or(ParseError::Timestamp)?;
    let day = day_text
        .parse::<u32>()
        .map_err(|_error| ParseError::Timestamp)?;
    let clock_parts = clock.split(':').collect::<Vec<_>>();
    let [hour, minute, second] = clock_parts.as_slice() else {
        return Err(ParseError::Timestamp);
    };
    let time = (
        hour.parse::<u32>()
            .map_err(|_error| ParseError::Timestamp)?,
        minute
            .parse::<u32>()
            .map_err(|_error| ParseError::Timestamp)?,
        second
            .parse::<u32>()
            .map_err(|_error| ParseError::Timestamp)?,
    );
    let candidate = local_datetime(now.year(), month, day, time)?;
    let future_limit = now
        .checked_add_signed(TimeDelta::days(1))
        .ok_or(ParseError::Timestamp)?;
    let inferred = if candidate > future_limit {
        local_datetime(now.year().saturating_sub(1), month, day, time)?
    } else {
        candidate
    };
    Ok((inferred, rest))
}

/// Constructs one naive local timestamp.
///
/// # Errors
///
/// Returns [`ParseError::Timestamp`] for an impossible date or time.
fn local_datetime(
    year: i32,
    month: u32,
    day: u32,
    (hour, minute, second): (u32, u32, u32),
) -> Result<NaiveDateTime, ParseError> {
    NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|date| date.and_hms_opt(hour, minute, second))
        .ok_or(ParseError::Timestamp)
}

/// Splits process and component prefixes while preserving ordinary message text.
fn prefixes(text: &str) -> (Option<String>, Option<u32>, Option<String>, String) {
    let mut rest = text.trim();
    let mut process = None;
    let mut pid = None;
    if let Some((head, tail)) = rest.split_once(": ")
        && let Some((name, number)) = head
            .strip_suffix(']')
            .and_then(|prefix| prefix.split_once('['))
        && let Ok(parsed) = number.parse::<u32>()
    {
        process = Some(name.to_owned());
        pid = Some(parsed);
        rest = tail;
    }
    let component = rest.split_once(": ").and_then(|(head, tail)| {
        head.contains("::").then(|| {
            rest = tail;
            head.to_owned()
        })
    });
    (process, pid, component, rest.to_owned())
}

/// Maps a three-letter month name to its calendar number.
const fn month_number(month: &str) -> Option<u32> {
    match month.as_bytes() {
        b"Jan" => Some(1),
        b"Feb" => Some(2),
        b"Mar" => Some(3),
        b"Apr" => Some(4),
        b"May" => Some(5),
        b"Jun" => Some(6),
        b"Jul" => Some(7),
        b"Aug" => Some(8),
        b"Sep" => Some(9),
        b"Oct" => Some(10),
        b"Nov" => Some(11),
        b"Dec" => Some(12),
        _ => None,
    }
}

/// Maps a router severity word to the fixed level set; an unknown word is `other`.
fn normalize_level(level: &str) -> String {
    match level.to_ascii_lowercase().as_str() {
        "error" | "critical" => "error",
        "warning" => "warning",
        "info" => "info",
        "debug" => "debug",
        _ => "other",
    }
    .to_owned()
}

/// Expands a short router label when no severity word is present.
fn level_from_label(label: Option<&str>) -> String {
    match label {
        Some("E" | "C") => "error",
        Some("W") => "warning",
        Some("D") => "debug",
        Some("I" | _) | None => "info",
    }
    .to_owned()
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions are not rendered API documentation"
)]
mod tests {
    use std::time::SystemTime;

    use chrono::{DateTime, Datelike as _, TimeDelta, Utc};
    use serde_json::json;

    use super::{ParseError, parse_records_now};

    /// Todo 10: `parse_records_now` places a bracket timestamp with kcc's own clock: the
    /// record parses, its prefixes split, and its year is this year or the last one, never
    /// more than a day ahead of now.
    #[test]
    fn parse_records_now_places_bracket_times_with_the_current_clock() -> Result<(), ParseError> {
        let response = json!({"log":{"7":{"message":{"label":"I","message":"[Nov 19 12:00:05] Opkg::Manager: /opt/etc/init.d/doinstall: [5/5] \"Entware\" installed!"}}}});

        let parsed = parse_records_now("router", &response)?;

        let now: DateTime<Utc> = SystemTime::now().into();
        assert_eq!(parsed.entries.len(), 1, "{:?}", parsed.entries);
        let Some((id, Some(record))) = parsed.entries.first() else {
            return Err(ParseError::Message);
        };
        assert_eq!(*id, 7);
        assert_eq!(record.component.as_deref(), Some("Opkg::Manager"));
        assert_eq!(
            record.message,
            "/opt/etc/init.d/doinstall: [5/5] \"Entware\" installed!"
        );
        let year = record.ts.year();
        assert!(
            year == now.year() || year == now.year().saturating_sub(1),
            "{year}"
        );
        let limit = now
            .naive_utc()
            .checked_add_signed(TimeDelta::days(1))
            .ok_or(ParseError::Timestamp)?;
        assert!(record.ts <= limit, "{}", record.ts);
        Ok(())
    }
}
