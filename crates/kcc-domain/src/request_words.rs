//! Words of a router CLI line, read from the fields of a validated request.

use kcc_catalog::ValidatedRequest;
use serde_json::Value;

use crate::{DomainError, Result};

/// The text field `field` of `request`.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when the request has no such text field.
pub(crate) fn text<'request>(
    request: &'request ValidatedRequest,
    field: &str,
) -> Result<&'request str> {
    optional_text(request, field).ok_or(DomainError::InvalidResponse)
}

/// The text field `field` of `request`, when it has one.
pub(crate) fn optional_text<'request>(
    request: &'request ValidatedRequest,
    field: &str,
) -> Option<&'request str> {
    request.value().get(field).and_then(Value::as_str)
}

/// The unsigned number field `field` of `request`, when it has one.
pub(crate) fn number(request: &ValidatedRequest, field: &str) -> Option<u64> {
    request.value().get(field).and_then(Value::as_u64)
}

/// The scalar field `field` of `value` as one word: a string as it is, any other value in
/// its JSON form.
pub(crate) fn field_word(value: &Value, field: &str) -> Option<String> {
    value.get(field).map(|item| {
        item.as_str()
            .map_or_else(|| item.to_string(), ToOwned::to_owned)
    })
}

/// The first member of `value` other than `no`: the argument of a one-argument command.
pub(crate) fn first_argument(value: &Value) -> Option<&Value> {
    value
        .as_object()?
        .iter()
        .find_map(|(key, item)| (key != "no").then_some(item))
}

/// `line` with the `no ` prefix when `value` removes the setting (`"no": true`).
pub(crate) fn negated(value: &Value, line: String) -> String {
    if value.get("no").and_then(Value::as_bool) == Some(true) {
        format!("no {line}")
    } else {
        line
    }
}
