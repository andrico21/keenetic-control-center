//! Read-back expectations for service and management listener writes.

use kcc_app::workflow::VerificationSpec;
use kcc_catalog::ValidatedRequest;
use serde_json::{Value, json};

use crate::{DomainError, Result, verification::action_without_state};

/// Builds expectations from validated non-secret command arguments.
pub(super) fn specs(request: &ValidatedRequest) -> Result<Vec<VerificationSpec>> {
    if action_without_state(&request.path).is_some() {
        return Ok(Vec::new());
    }
    let path = vec!["show".to_owned(), "rc".to_owned()];
    let enabled = request.value().get("no") != Some(&Value::Bool(true));
    if let Some(name) = request.path.strip_prefix("service ") {
        return Ok(vec![VerificationSpec::collection(
            path,
            "/service".to_owned(),
            if enabled {
                json!({"name":name,"enabled":true})
            } else {
                json!({"name":name})
            },
            enabled,
        )]);
    }
    let words = request.path.split_whitespace().collect::<Vec<_>>();
    let (field, expected) = match words.as_slice() {
        ["ip", listener, "port"] => (
            format!("/ip/{listener}/port"),
            request
                .value()
                .get("port")
                .or_else(|| request.value().get("number"))
                .cloned(),
        ),
        ["ip", listener, "security-level"] => (
            format!("/ip/{listener}/security-level"),
            request.value().get("level").cloned(),
        ),
        ["ip", "http", "ssl", "enable" | "redirect"] => {
            (format!("/{}", words.join("/")), Some(json!(enabled)))
        }
        ["ip", "http", "ssl", "port"] => (
            "/ip/http/ssl/port".to_owned(),
            request.value().get("port").cloned(),
        ),
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(vec![VerificationSpec::new(
        path,
        field,
        expected.ok_or(DomainError::InvalidResponse)?,
    )])
}
