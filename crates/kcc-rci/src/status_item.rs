//! Lenient reading of router status items: the level alone decides a failure.

use serde_json::Value;

use crate::{Level, StatusItem};

/// Reads one member of a `status` array; `None` when it has no `status` member.
pub(crate) fn parse(value: &Value) -> Option<StatusItem> {
    let object = value.as_object()?;
    let status = match object.get("status")?.as_str() {
        Some("message") => Level::Message,
        Some("warning") => Level::Warning,
        // `error`, a level this version does not know, or no level text at all.
        Some(_) | None => Level::Error,
    };
    Some(StatusItem {
        status,
        code: text(object.get("code")),
        ident: text(object.get("ident")),
        message: text(object.get("message")),
    })
}

/// A string or number member as text; anything else, or no member, is empty.
fn text(member: Option<&Value>) -> String {
    match member {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_)) | None => {
            String::new()
        }
    }
}
