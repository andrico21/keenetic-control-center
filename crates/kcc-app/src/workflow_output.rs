//! Serialization of workflow outputs after boundary scrubbing.

use kcc_rci::{RciBody, RciResponse};
use serde::{Serialize, Serializer};
use serde_json::{Value, json};

use super::{
    BatchChangeResult, ChangeResult, CliChangeResult, TerminalCliChangeResult, WorkflowError,
};
use crate::audit::receipt::AuditReceipt;

impl Serialize for ChangeResult {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        noting(json!({"unsaved":self.unsaved}), &self.audit).serialize(serializer)
    }
}

impl Serialize for CliChangeResult {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let responses = self.responses.iter().map(body_value).collect::<Vec<_>>();
        noting(
            json!({"unsaved":self.unsaved, "responses":responses}),
            &self.audit,
        )
        .serialize(serializer)
    }
}

impl Serialize for TerminalCliChangeResult {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        json!({"responses":self.responses.iter().map(body_value).collect::<Vec<_>>()})
            .serialize(serializer)
    }
}

impl Serialize for BatchChangeResult {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let responses = self
            .responses
            .iter()
            .map(|response| match response {
                Ok(value) => response_value(value),
                Err(error) => json!({"error":error.to_string()}),
            })
            .collect::<Vec<_>>();
        noting(
            json!({"unsaved":self.unsaved, "responses":responses}),
            &self.audit,
        )
        .serialize(serializer)
    }
}

/// `document` with `"audit_pending": true` while the change's audit entry is still queued.
fn noting(mut document: Value, audit: &AuditReceipt) -> Value {
    if audit.is_pending()
        && let Value::Object(object) = &mut document
    {
        drop(object.insert("audit_pending".to_owned(), Value::Bool(true)));
    }
    document
}

impl Serialize for WorkflowError {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

/// Uses the scrubbed JSON as the serialization source of truth.
fn response_value(response: &RciResponse) -> Value {
    response.value.clone()
}

/// Preserves the router response body kind without adding raw diagnostic fields.
fn body_value(body: &RciBody) -> Value {
    match body {
        RciBody::Json(response) => response_value(response),
        RciBody::Text(text) => Value::String(text.clone()),
        _ => Value::Null,
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions establish the output redaction contract"
)]
mod tests {
    use core::error::Error;

    use kcc_catalog::SecretValue;
    use kcc_rci::{RciBody, RciError, RciResponse};
    use secrecy::SecretString;
    use serde_json::json;

    use super::super::{CliChangeResult, WorkflowError, scrub_error, scrub_response};
    use crate::audit::receipt::{AuditReceipt, Pending};

    /// Router-echoed secrets disappear from JSON, status copies, error detail and serialization.
    #[test]
    fn router_echoes_are_scrubbed_before_public_results() -> Result<(), Box<dyn Error>> {
        let secret = "secret \"quoted\" \\ text";
        let protected = SecretValue::argument("password", SecretString::from(secret.to_owned()));
        let mut response = RciResponse::from_value(json!({"status":[{
            "status":"warning", "code":"1", "ident":"test", "message":format!("echo {secret}")
        }]}))?;
        scrub_response(&protected, &mut response);
        assert_eq!(
            response
                .statuses
                .first()
                .map(|(_pointer, status)| status.message.as_str()),
            Some("echo <redacted>")
        );
        assert_eq!(
            response
                .warnings
                .first()
                .map(|(_pointer, status)| status.message.as_str()),
            Some("echo <redacted>")
        );
        let result = CliChangeResult {
            unsaved: true,
            responses: vec![RciBody::Json(response)],
            audit: AuditReceipt::Pending(Pending::lost()),
        };
        assert!(serde_json::to_string(&result)?.contains("echo <redacted>"));
        let failure = RciResponse::from_value(json!({"status":[{
            "status":"error", "code":"1", "ident":"test", "message":format!("echo {secret}")
        }]}));
        let error = match failure {
            Err(error) => scrub_error(&protected, error),
            Ok(_) => return Err("error status accepted".into()),
        };
        match &error {
            RciError::Rci {
                pointer: _,
                code: _,
                ident: _,
                message,
            } => assert_eq!(message, "echo <redacted>"),
            _ => return Err("wrong error category".into()),
        }
        let workflow = WorkflowError::Rci(error);
        assert!(!serde_json::to_string(&workflow)?.contains(secret));
        Ok(())
    }
}
