//! Fresh running-configuration expectations for logging settings.

use kcc_app::workflow::VerificationSpec;
use kcc_catalog::ValidatedRequest;
use serde_json::{Value, json};

use crate::{DomainError, Result};

/// Builds expectations without including the stateless log-clear action.
pub(super) fn specs(request: &ValidatedRequest) -> Result<Vec<VerificationSpec>> {
    let path = vec!["show".to_owned(), "rc".to_owned()];
    let enabled = request.value().get("no") != Some(&Value::Bool(true));
    let spec = match request.path.as_str() {
        "system log clear" => return Ok(Vec::new()),
        "system log reduction" => {
            VerificationSpec::new(path, "/system/log/reduction".to_owned(), json!(enabled))
        }
        "system log server" => {
            let mut expected = request.value().clone();
            let fields = expected
                .as_object_mut()
                .ok_or(DomainError::InvalidResponse)?;
            drop(fields.remove("no"));
            VerificationSpec::collection(path, "/system/log/server".to_owned(), expected, enabled)
        }
        "system log suppress" => VerificationSpec::collection(
            path,
            "/system/log/suppress".to_owned(),
            request
                .value()
                .get("ident")
                .cloned()
                .ok_or(DomainError::InvalidResponse)?,
            enabled,
        ),
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(vec![spec])
}
