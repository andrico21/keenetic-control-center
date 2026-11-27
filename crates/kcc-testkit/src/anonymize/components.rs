//! Component lists and states: a component's `name` and `description` come from the
//! firmware, so they are protocol words, kept (through the text rules) and never learned.

use serde_json::{Map, Value};

use super::{AnonymizeError, Anonymizer, Context, classify, named_context};

/// Keys whose string values are component words inside a components answer.
const COMPONENT_WORDS: &[&str] = &["name", "description"];

/// Anonymizes a components answer held under `parent`: as [`Anonymizer::json`], except
/// that the string values of [`COMPONENT_WORDS`] keys, at any depth below plain members,
/// only go through [`Anonymizer::text`].
///
/// # Errors
///
/// [`AnonymizeError::AddressSpaceExhausted`] when the documentation ranges run out.
pub(super) fn anonymize(
    anonymizer: &mut Anonymizer,
    value: &Value,
    parent: Option<&str>,
) -> Result<Value, AnonymizeError> {
    Ok(match value {
        Value::Object(object) => {
            let mut result = Map::new();
            for (key, member) in object {
                let context = classify(key);
                let scrubbed = match (member, named_context(parent, key)) {
                    (Value::String(word), _) if COMPONENT_WORDS.contains(&key.as_str()) => {
                        Value::String(anonymizer.text(word)?)
                    }
                    (Value::Object(inner), Some(names)) => {
                        anonymizer.named_members(inner, names)?
                    }
                    (Value::Object(_) | Value::Array(_), _) if context == Context::Plain => {
                        anonymize(anonymizer, member, Some(key))?
                    }
                    (
                        Value::Null
                        | Value::Bool(_)
                        | Value::Number(_)
                        | Value::String(_)
                        | Value::Object(_)
                        | Value::Array(_),
                        _,
                    ) => anonymizer.value(member, context)?,
                };
                drop(result.insert(anonymizer.key(key)?, scrubbed));
            }
            Value::Object(result)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| anonymize(anonymizer, item, parent))
                .collect::<Result<_, _>>()?,
        ),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            anonymizer.value(value, Context::Plain)?
        }
    })
}
