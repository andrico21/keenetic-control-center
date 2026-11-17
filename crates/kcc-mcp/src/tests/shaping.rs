//! Result truncation: what a cut result keeps and what it signals.

use core::error::Error;

use kcc_app::settings::{McpConfig, PrivacyConfig};
use serde_json::{Value, json};

use super::fixture::Fixture;
use crate::support::{shape::shape, truncate::Shaping};

/// A failure reply whose bulky array exceeds `cap`.
fn oversized_failure() -> Value {
    json!({
        "error": "management_applied_fail_safe_armed",
        "message": "the fail-safe timer is armed",
        "field": "interface",
        "unsaved": true,
        "persists_immediately": false,
        "audit_pending": true,
        "request_id": "request",
        "items": (0..200).map(|index| json!({"index": index, "text": "x".repeat(40)})).collect::<Vec<_>>()
    })
}

/// E-04: a truncated failure keeps its code, message, field and flags; only the bulky array
/// is cut, the cut is flagged, and a tool without a cursor input gets no cursor.
#[tokio::test]
async fn truncated_failure_keeps_codes_and_cuts_only_the_array() -> Result<(), Box<dyn Error>> {
    let mut config = McpConfig::default();
    config.max_result_bytes = 1024;
    let fixture = Fixture::spawn(config, PrivacyConfig::default()).await?;
    let text = shape(
        fixture.server(),
        oversized_failure(),
        Shaping::new(Some("request")),
    )
    .map_err(|error| format!("shape failed: {error:?}"))?;
    assert!(text.len() <= 1024, "{} bytes", text.len());
    let value: Value = serde_json::from_str(&text)?;
    for (key, expected) in oversized_failure()
        .as_object()
        .ok_or("object")?
        .iter()
        .filter(|(key, _value)| *key != "items")
    {
        assert_eq!(value.get(key), Some(expected), "{key} in {value}");
    }
    assert_eq!(value.get("truncated"), Some(&Value::Bool(true)));
    assert_eq!(value.get("next_cursor"), None);
    let kept = value
        .get("items")
        .and_then(Value::as_array)
        .ok_or("items kept")?;
    assert!(!kept.is_empty() && kept.len() < 200, "{} items", kept.len());
    fixture.shutdown().await?;
    Ok(())
}

/// E-04: a reply that is not an array but too big still says it was truncated and keeps
/// its scalar members.
#[tokio::test]
async fn truncated_object_keeps_scalars_and_flags_the_cut() -> Result<(), Box<dyn Error>> {
    let mut config = McpConfig::default();
    config.max_result_bytes = 256;
    let fixture = Fixture::spawn(config, PrivacyConfig::default()).await?;
    let reply = json!({"job_id": "job-1", "status": "done", "log": "y".repeat(4096)});
    let text = shape(fixture.server(), reply, Shaping::new(Some("request")))
        .map_err(|error| format!("shape failed: {error:?}"))?;
    let value: Value = serde_json::from_str(&text)?;
    assert_eq!(value.get("job_id"), Some(&json!("job-1")), "{value}");
    assert_eq!(value.get("status"), Some(&json!("done")), "{value}");
    assert_eq!(value.get("truncated"), Some(&Value::Bool(true)));
    assert_eq!(value.get("log"), None);
    fixture.shutdown().await?;
    Ok(())
}

/// E-04: a cut page of a tool with a `cursor` input names the real next offset: the
/// offset of the page plus the items kept.
#[tokio::test]
async fn truncated_page_names_the_next_offset() -> Result<(), Box<dyn Error>> {
    let mut config = McpConfig::default();
    config.max_result_bytes = 1024;
    let fixture = Fixture::spawn(config, PrivacyConfig::default()).await?;
    let shaping = Shaping::new(Some("request")).with_input(&[], Some(40));
    let text = shape(fixture.server(), oversized_failure(), shaping)
        .map_err(|error| format!("shape failed: {error:?}"))?;
    let value: Value = serde_json::from_str(&text)?;
    let kept = value
        .get("items")
        .and_then(Value::as_array)
        .ok_or("items kept")?
        .len();
    assert_eq!(
        value.get("next_cursor"),
        Some(&json!((40 + kept).to_string())),
        "{value}"
    );
    fixture.shutdown().await?;
    Ok(())
}
