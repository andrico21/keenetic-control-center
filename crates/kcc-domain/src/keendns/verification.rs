//! KeenDNS and remote-access read-back expectations.

use kcc_app::workflow::{PresencePredicate, VerificationSpec};
use serde_json::{Value, json};

use crate::{ChangeOp, DomainError, Result, pointer};

/// Builds expectations for the selected registration or proxy context.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
pub(super) fn specs(operation: &ChangeOp) -> Result<Vec<VerificationSpec>> {
    let first = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let path = vec!["show".to_owned(), "rc".to_owned()];
    let text = |key| {
        first
            .value()
            .get(key)
            .and_then(Value::as_str)
            .ok_or(DomainError::InvalidResponse)
    };
    let spec = match first.path.as_str() {
        "cloud control2 security-level" => VerificationSpec::new(
            path,
            "/cloud/control2/security-level".to_owned(),
            first
                .value()
                .get("level")
                .cloned()
                .ok_or(DomainError::InvalidResponse)?,
        ),
        "ndns book-name" | "ndns drop-name" => {
            let present = first.path == "ndns book-name";
            VerificationSpec::collection(
                path,
                "/ndns/book-name".to_owned(),
                json!({"name":text("name")?,"domain":text("domain")?}),
                present,
            )
        }
        "ip http proxy" => {
            let name = pointer::escape(text("name")?);
            VerificationSpec::presence(
                path,
                format!("/ip/http/proxy/{name}"),
                if first.value().get("no") == Some(&Value::Bool(true)) {
                    PresencePredicate::Absent
                } else {
                    PresencePredicate::Present
                },
            )
        }
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(vec![spec])
}

/// The read-back of one proxy's upstream, in the router's configuration shape.
pub(super) fn upstream(proxy: &str, expected: Value) -> VerificationSpec {
    VerificationSpec::new(
        vec!["show".to_owned(), "rc".to_owned()],
        format!("/ip/http/proxy/{}/upstream", pointer::escape(proxy)),
        expected,
    )
}
