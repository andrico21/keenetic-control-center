//! Tool-argument boundary checks shared by every tool family.

use serde_json::Value;

use crate::McpFailure;

/// Longest router profile id.
pub(crate) const MAX_HOST_CHARS: usize = 32;
/// Longest catalog command path.
pub(crate) const MAX_PATH_CHARS: usize = 512;
/// Longest catalog search query.
pub(crate) const MAX_QUERY_CHARS: usize = 256;
/// Longest CLI line.
pub(crate) const MAX_LINE_CHARS: usize = 2048;
/// Most projected result fields.
const MAX_FIELDS: usize = 64;
/// Most items in one raw RCI batch.
pub(crate) const MAX_BATCH_ITEMS: usize = 64;

/// Returns an empty JSON object, the default request body.
pub(crate) fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

/// Accepts a lowercase router profile slug.
pub(crate) fn valid_host(host: &str) -> Result<(), McpFailure> {
    if !(1..=MAX_HOST_CHARS).contains(&host.len())
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(McpFailure::InvalidArguments);
    }
    Ok(())
}

/// Accepts non-empty text without control characters up to `max_chars`.
pub(crate) fn valid_text(value: &str, max_chars: usize) -> Result<(), McpFailure> {
    let length = value.chars().count();
    if !(1..=max_chars).contains(&length) || value.chars().any(char::is_control) {
        return Err(McpFailure::InvalidArguments);
    }
    Ok(())
}

/// Accepts a persisted job or migration identifier.
pub(crate) fn valid_job_id(id: &str) -> Result<(), McpFailure> {
    if id.len() > 64
        || id.is_empty()
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(McpFailure::InvalidArguments);
    }
    Ok(())
}

/// Checks the shared raw RCI request shape.
pub(crate) fn validate_rci_input(
    host: &str,
    catalog_path: &str,
    path: &[String],
    value: &Value,
) -> Result<(), McpFailure> {
    valid_host(host)?;
    valid_text(catalog_path, MAX_PATH_CHARS)?;
    if path.is_empty() || path.len() > 16 {
        return Err(McpFailure::InvalidArguments);
    }
    for segment in path {
        valid_text(segment, 64)?;
    }
    valid_value_size(value)
}

/// Bounds one JSON request body.
pub(crate) fn valid_value_size(value: &Value) -> Result<(), McpFailure> {
    let bytes = serde_json::to_vec(value).map_err(|_error| McpFailure::InvalidArguments)?;
    if bytes.len() > 900 * 1024 {
        return Err(McpFailure::InvalidArguments);
    }
    Ok(())
}

/// Bounds a field projection list.
pub(crate) fn validate_fields(fields: Option<&[String]>) -> Result<(), McpFailure> {
    let Some(fields) = fields else {
        return Ok(());
    };
    if fields.len() > MAX_FIELDS {
        return Err(McpFailure::InvalidArguments);
    }
    for field in fields {
        valid_text(field, 64)?;
    }
    Ok(())
}

/// Parses a decimal offset cursor.
pub(crate) fn parse_cursor(cursor: Option<&str>) -> Result<usize, McpFailure> {
    cursor
        .unwrap_or("0")
        .parse::<usize>()
        .map_err(|_error| McpFailure::InvalidArguments)
}

/// Keeps one page of `items`.
pub(crate) fn paginate(
    items: &mut Vec<Value>,
    cursor: Option<&str>,
    limit: Option<u16>,
) -> Result<(), McpFailure> {
    let offset = parse_cursor(cursor)?;
    let count = usize::from(limit.unwrap_or(50).min(100));
    if offset >= items.len() {
        items.clear();
    } else {
        drop(items.drain(..offset));
        items.truncate(count);
    }
    Ok(())
}
