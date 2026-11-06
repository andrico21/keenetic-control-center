//! Explicit router agreement confirmation and acknowledgement audit.

use std::time::{SystemTime, UNIX_EPOCH};

use kcc_app::audit::AuditEvent;
use kcc_rci::{RciBody, RciClient, RciError, RciPath};
use serde_json::{Value, json};

use super::{ApplyError, ApplyRequest};

/// Requires confirmation of the exact current document before accepting an agreement.
///
/// # Errors
/// Returns missing confirmation or malformed agreement responses.
// cancel-safe: only reads router documents.
pub(super) async fn pending(
    request: &ApplyRequest,
    client: &RciClient,
) -> Result<Vec<&'static str>, ApplyError> {
    let mut pending = Vec::new();
    for agreement in ["dpn", "eula"] {
        let path = RciPath::from_segments(["show", agreement, "list"])
            .map_err(|_error| ApplyError::Validation)?;
        let response = match client.get(&path, &()).await {
            Ok(RciBody::Json(response)) => response,
            Err(RciError::NotFound) => continue,
            _ => return Err(ApplyError::AgreementRequired),
        };
        if response.value.get("accepted").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let document_path = RciPath::from_segments(["show", agreement, "document"])
            .map_err(|_error| ApplyError::Validation)?;
        let RciBody::Json(document) = client
            .get(&document_path, &())
            .await
            .map_err(|_error| ApplyError::AgreementRequired)?
        else {
            return Err(ApplyError::AgreementRequired);
        };
        let text = document
            .value
            .get("text")
            .and_then(Value::as_str)
            .ok_or(ApplyError::AgreementRequired)?;
        if request
            .options
            .agreements
            .get(agreement)
            .map(String::as_str)
            != Some(text)
        {
            return Err(ApplyError::AgreementRequired);
        }
        pending.push(agreement);
    }
    Ok(pending)
}

/// Records explicit acknowledgement without document or credential text.
///
/// # Errors
/// Returns audit persistence failure.
// NOT cancel-safe: the audit writer may append after cancellation.
pub(super) async fn audit(request: &ApplyRequest, action: &str) -> Result<(), ApplyError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let event = AuditEvent::new(timestamp, request.actor.clone(), action.to_owned())
        .with_router(request.target.clone())
        .with_params(json!({"confirmed":true}))
        .with_result("confirmed".to_owned(), request.plan.plan_id.clone());
    drop(
        request
            .audit
            .append(event)
            .await
            .map_err(|_error| ApplyError::Workflow)?,
    );
    Ok(())
}
