//! Named account and tag expectations.

use kcc_app::workflow::VerificationSpec;
use serde_json::{Value, json};

use crate::{ChangeOp, DomainError, Result};

/// Keeps secret checks and verifies the intended account and each changed tag.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
pub(super) fn specs(operation: &ChangeOp, name: &str) -> Result<Vec<VerificationSpec>> {
    let first = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let mut specs = operation.verify.clone();
    specs.push(VerificationSpec::collection(
        vec!["show".to_owned(), "rc".to_owned()],
        "/user".to_owned(),
        json!({"name":name}),
        first.value().get("no") != Some(&Value::Bool(true)),
    ));
    for request in operation
        .requests
        .iter()
        .filter(|request| request.path == "user tag")
    {
        let tag = request
            .value()
            .get("tag")
            .ok_or(DomainError::InvalidResponse)?;
        specs.push(VerificationSpec::collection(
            vec!["show".to_owned(), "rc".to_owned()],
            "/user".to_owned(),
            json!({"name":name,"tag":[tag]}),
            request.value().get("no") != Some(&Value::Bool(true)),
        ));
    }
    Ok(specs)
}
