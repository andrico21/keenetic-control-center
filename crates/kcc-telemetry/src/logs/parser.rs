//! Router log wire-format parsing.

use chrono::{DateTime, Datelike as _, FixedOffset, NaiveDate, TimeDelta, TimeZone as _};
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
    /// A record id is not an unsigned decimal integer.
    #[error("router log record id is malformed")]
    Id,
    /// A record has no usable message text.
    #[error("router log record message is malformed")]
    Message,
    /// A timestamp is absent or malformed.
    #[error("router log record timestamp is malformed")]
    Timestamp,
}

/// Parses every numeric record in one router response in ascending id order.
///
/// # Errors
///
/// Returns [`ParseError`] when the response or any record is malformed.
#[inline]
pub fn parse_records(
    router: &str,
    response: &Value,
    router_now: DateTime<FixedOffset>,
) -> Result<Vec<LogRecord>, ParseError> {
    let entries = response
        .get("log")
        .and_then(Value::as_object)
        .ok_or(ParseError::Response)?;
    let mut records = entries
        .iter()
        .map(|(text_id, value)| {
            let numeric_id = text_id.parse::<u64>().map_err(|_error| ParseError::Id)?;
            parse_record(router, numeric_id, value, router_now)
        })
        .collect::<Result<Vec<_>, _>>()?;
    records.sort_by_key(|record| record.id);
    Ok(records)
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
    router_now: DateTime<FixedOffset>,
) -> Result<LogRecord, ParseError> {
    let body = value.get("message").unwrap_or(value);
    let raw = body
        .get("message")
        .and_then(Value::as_str)
        .ok_or(ParseError::Message)?;
    let (ts, text) = timestamp(value, raw, router_now)?;
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

/// Selects an explicit timestamp or parses the conventional bracket prefix.
///
/// # Errors
///
/// Returns [`ParseError::Timestamp`] when neither timestamp representation is usable.
fn timestamp<'text>(
    value: &Value,
    raw: &'text str,
    router_now: DateTime<FixedOffset>,
) -> Result<(DateTime<FixedOffset>, &'text str), ParseError> {
    if let Some(text) = value.get("time").and_then(Value::as_str) {
        let parsed = DateTime::parse_from_rfc3339(text).map_err(|_error| ParseError::Timestamp)?;
        return Ok((parsed, raw));
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
    let candidate = local_datetime(router_now, router_now.year(), month, day, time)?;
    let future_limit = router_now
        .checked_add_signed(TimeDelta::days(1))
        .ok_or(ParseError::Timestamp)?;
    let inferred = if candidate > future_limit {
        local_datetime(
            router_now,
            router_now.year().saturating_sub(1),
            month,
            day,
            time,
        )?
    } else {
        candidate
    };
    Ok((inferred, rest))
}

/// Constructs one unambiguous fixed-offset local timestamp.
///
/// # Errors
///
/// Returns [`ParseError::Timestamp`] for an impossible date or time.
fn local_datetime(
    now: DateTime<FixedOffset>,
    year: i32,
    month: u32,
    day: u32,
    (hour, minute, second): (u32, u32, u32),
) -> Result<DateTime<FixedOffset>, ParseError> {
    let naive = NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|date| date.and_hms_opt(hour, minute, second))
        .ok_or(ParseError::Timestamp)?;
    now.timezone()
        .from_local_datetime(&naive)
        .single()
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

/// Normalizes router severity words.
fn normalize_level(level: &str) -> String {
    level.to_ascii_lowercase()
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
