//! Structured NTP mutations translated to mutable simulator configuration.

use serde_json::Value;

/// Decodes the supported structured NTP write shapes.
pub(crate) fn command(path: &str, body: &Value) -> Option<String> {
    if let Some(server) = body.get("server").and_then(Value::as_str) {
        return Some(format!("ntp server {server}"));
    }
    if path == "ntp/master" {
        let enabled = body.get("no") != Some(&Value::Bool(true));
        return Some(
            if enabled {
                "ntp master"
            } else {
                "no ntp master"
            }
            .to_owned(),
        );
    }
    body.get("period")
        .and_then(Value::as_u64)
        .map(|seconds| format!("ntp sync-period {seconds}"))
}
