//! Component lists and states: a component's `name` and `description` come from the
//! firmware, so they are protocol words, kept (through the text rules) and never learned.

use serde_json::{Map, Value};

use super::{AnonymizeError, Anonymizer, Context, classify};

/// Keys whose string values are component words inside a components answer.
const COMPONENT_WORDS: &[&str] = &["name", "description"];

/// Anonymizes a components answer: as [`Anonymizer::json`], except that the string values
/// of [`COMPONENT_WORDS`] keys, at any depth below plain members, only go through
/// [`Anonymizer::text`].
///
/// # Errors
///
/// [`AnonymizeError::AddressSpaceExhausted`] when the documentation ranges run out.
pub(super) fn anonymize(
    anonymizer: &mut Anonymizer,
    value: &Value,
) -> Result<Value, AnonymizeError> {
    Ok(match value {
        Value::Object(object) => {
            let mut result = Map::new();
            for (key, member) in object {
                let context = classify(key);
                let scrubbed = match member {
                    Value::String(word) if COMPONENT_WORDS.contains(&key.as_str()) => {
                        Value::String(anonymizer.text(word)?)
                    }
                    Value::Object(_) | Value::Array(_) if context == Context::Plain => {
                        anonymize(anonymizer, member)?
                    }
                    Value::Null
                    | Value::Bool(_)
                    | Value::Number(_)
                    | Value::String(_)
                    | Value::Object(_)
                    | Value::Array(_) => anonymizer.value(member, context)?,
                };
                drop(result.insert(anonymizer.text(key)?, scrubbed));
            }
            Value::Object(result)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| anonymize(anonymizer, item))
                .collect::<Result<_, _>>()?,
        ),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            anonymizer.value(value, Context::Plain)?
        }
    })
}
