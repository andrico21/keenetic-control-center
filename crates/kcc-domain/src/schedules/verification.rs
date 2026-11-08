//! Intended schedule fields, independent of collection ordering.

use serde_json::{Map, Value, json};

use crate::{ChangeOp, DomainError, Result};

/// Builds the requested row without unrelated schedule defaults.
pub(super) fn expected(operation: &ChangeOp, name: &str) -> Result<Value> {
    let mut row = Map::new();
    drop(row.insert("name".to_owned(), json!(name)));
    for request in operation.requests.iter().skip(1) {
        match request.path.as_str() {
            "schedule description" => {
                drop(
                    row.insert(
                        "description".to_owned(),
                        request
                            .value
                            .get("description")
                            .cloned()
                            .ok_or(DomainError::InvalidResponse)?,
                    ),
                );
            }
            "schedule action" => {
                drop(row.insert("action".to_owned(), json!([request.value])));
            }
            _ => return Err(DomainError::InvalidResponse),
        }
    }
    Ok(Value::Object(row))
}
