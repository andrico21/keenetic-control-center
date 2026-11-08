//! Assumed NTP running-configuration projection.

use serde_json::{Map, Value, json};

use super::matching;

/// Reads server, master and period values from the mutable AST.
pub(super) fn project(lines: &[Vec<String>]) -> Value {
    let mut fields = Map::new();
    drop(fields.insert("master".to_owned(), json!(false)));
    for words in matching(lines, &["ntp"]) {
        match words {
            [field] if field == "master" => {
                drop(fields.insert("master".to_owned(), json!(true)));
            }
            [field, server] if field == "server" => {
                drop(fields.insert("server".to_owned(), json!(server)));
            }
            [field, period] if field == "sync-period" => {
                if let Ok(seconds) = period.parse::<u32>() {
                    drop(fields.insert("sync-period".to_owned(), json!(seconds)));
                }
            }
            _ => {}
        }
    }
    Value::Object(fields)
}
