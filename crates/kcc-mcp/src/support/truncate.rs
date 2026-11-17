//! The per-call inputs of result shaping, field projection, and the byte-budget cut.

use serde_json::{Map, Value, json};

use crate::McpFailure;

/// Scalar members a cut result keeps: the failure code, the fail-safe message and field,
/// the outcome flags of a write, and the handle and state of a job.
const KEPT: [&str; 12] = [
    "error",
    "message",
    "field",
    "unsaved",
    "persists_immediately",
    "audit_pending",
    "request_id",
    "applied",
    "rebooting",
    "factory_reset",
    "job_id",
    "status",
];

/// Reply member that reports router statuses; a projection never strips it.
const STATUSES: &str = "statuses";

/// What the parsed tool input contributes to shaping its result.
#[derive(Clone, Copy, Default)]
pub(crate) struct Shaping<'call> {
    /// Correlation id of the call.
    request_id: Option<&'call str>,
    /// Requested item members; empty keeps whole items.
    fields: &'call [String],
    /// Offset of the page the call asked for, for a tool with a `cursor` input.
    cursor: Option<usize>,
}

impl<'call> Shaping<'call> {
    /// Shaping for a call without projection or paging.
    pub(crate) const fn new(request_id: Option<&'call str>) -> Self {
        Self {
            request_id,
            fields: &[],
            cursor: None,
        }
    }

    /// The same call projecting its items to `fields` and paging from `cursor`.
    pub(crate) const fn with_input(self, fields: &'call [String], cursor: Option<usize>) -> Self {
        Self {
            request_id: self.request_id,
            fields,
            cursor,
        }
    }

    /// Keeps only the requested members of every object item of a top-level array.
    pub(super) fn project(&self, value: &mut Value) {
        if self.fields.is_empty() {
            return;
        }
        let Value::Object(object) = value else {
            return;
        };
        for (key, member) in object.iter_mut() {
            if key == STATUSES {
                continue;
            }
            if let Value::Array(items) = member {
                for item in items {
                    if let Value::Object(members) = item {
                        members.retain(|name, _nested| self.fields.contains(name));
                    }
                }
            }
        }
    }

    /// The result cut to `cap` bytes: the kept scalar members, a `truncated` flag, and the
    /// longest prefix of the bulkiest array that fits, with the next offset when the tool
    /// pages. Refused when the kept scalars alone exceed `cap`.
    ///
    /// # Errors
    ///
    /// Returns an `McpFailure` naming the refusal or failure to report to the client.
    pub(super) fn cut(&self, value: &Value, cap: usize) -> Result<String, McpFailure> {
        let object = value.as_object();
        let mut kept = Map::new();
        for key in KEPT {
            if let Some(scalar) = object
                .and_then(|members| members.get(key))
                .filter(|member| !member.is_array() && !member.is_object())
            {
                drop(kept.insert(key.to_owned(), scalar.clone()));
            }
        }
        drop(kept.insert("truncated".to_owned(), Value::Bool(true)));
        if !kept.contains_key("request_id") {
            drop(kept.insert("request_id".to_owned(), json!(self.request_id)));
        }
        let base = encode(&Value::Object(kept.clone()), cap).ok_or(McpFailure::Internal)?;
        let Some((key, items)) = object.and_then(bulkiest_array) else {
            return Ok(base);
        };
        let page = |count: usize| {
            let mut cut = kept.clone();
            drop(cut.insert(
                key.clone(),
                Value::Array(items.iter().take(count).cloned().collect()),
            ));
            let following = match self.cursor {
                Some(offset) if count > 0 && count < items.len() => {
                    Some(json!(offset.saturating_add(count).to_string()))
                }
                Some(_offset) if count == items.len() => object
                    .and_then(|members| members.get("next_cursor"))
                    .cloned(),
                Some(_) | None => None,
            };
            if let Some(next) = following {
                drop(cut.insert("next_cursor".to_owned(), next));
            }
            encode(&Value::Object(cut), cap)
        };
        let (mut low, mut high, mut best) = (0, items.len(), None);
        while low <= high {
            let middle = low.midpoint(high);
            if let Some(text) = page(middle) {
                best = Some(text);
                low = middle.saturating_add(1);
            } else if middle == 0 {
                break;
            } else {
                high = middle.saturating_sub(1);
            }
        }
        Ok(best.unwrap_or(base))
    }
}

/// `value` encoded, when it fits `cap` bytes.
fn encode(value: &Value, cap: usize) -> Option<String> {
    serde_json::to_string(value)
        .ok()
        .filter(|text| text.len() <= cap)
}

/// The top-level array member with the largest encoding, outside the kept members.
fn bulkiest_array(object: &Map<String, Value>) -> Option<(String, &Vec<Value>)> {
    object
        .iter()
        .filter(|(key, _member)| !KEPT.contains(&key.as_str()))
        .filter_map(|(key, member)| member.as_array().map(|items| (key.clone(), items)))
        .max_by_key(|(_key, items)| serde_json::to_string(items).map_or(0, |text| text.len()))
}
