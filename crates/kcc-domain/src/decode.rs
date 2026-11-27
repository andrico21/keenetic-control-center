//! Decoding of router answers, with one value-free warning per failure.

use std::{
    sync::{LazyLock, Mutex, PoisonError},
    time::Instant,
};

use kcc_rci::{Admit, DecodeDetail, DecodeProblem, Deduper, RciBody, decode_value, not_json};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{DomainError, Result};

/// Collapses repeated warnings of the same router, resource and problem kind.
static SEEN: LazyLock<Mutex<Deduper>> = LazyLock::new(|| Mutex::new(Deduper::default()));

/// Decodes `value`, the answer to `resource` of the router logged as `router`.
///
/// # Errors
///
/// Returns [`DomainError::UnreadableAnswer`] naming the first value that does not fit `T`.
pub(crate) fn value<T>(router: &str, resource: &str, value: &Value) -> Result<T>
where
    T: DeserializeOwned,
{
    decode_value(resource, value).map_err(|detail| unreadable(router, detail))
}

/// Decodes a JSON `body`; a text body is not JSON.
///
/// # Errors
///
/// Returns [`DomainError::UnreadableAnswer`] for a text body or a value that does not fit
/// `T`, and [`DomainError::InvalidResponse`] for a body kind kcc does not know.
pub(crate) fn body<T>(router: &str, resource: &str, body: &RciBody) -> Result<T>
where
    T: DeserializeOwned,
{
    if let RciBody::Text(text) = body {
        return Err(unreadable(router, not_json(resource, text.as_bytes())));
    }
    let RciBody::Json(response) = body else {
        return Err(DomainError::InvalidResponse);
    };
    value(router, resource, &response.value)
}

/// Logs `detail` once per window and wraps it.
fn unreadable(router: &str, detail: Box<DecodeDetail>) -> DomainError {
    let problem = kind(&detail.problem);
    let key = (
        router.to_owned(),
        "decode".to_owned(),
        detail.resource.clone(),
        problem.to_owned(),
    );
    let admit = SEEN
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .admit(key, Instant::now());
    if let Admit::Log { suppressed } = admit {
        tracing::warn!(
            target: "kcc_domain::decode",
            router = %router,
            resource = %detail.resource,
            path = %detail.path,
            problem = %problem,
            suppressed,
            "the router's answer could not be read"
        );
    }
    DomainError::UnreadableAnswer(detail)
}

/// The name of the kind of `problem`, never a value.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "DecodeProblem is non_exhaustive; a kind kcc does not know yet is `other`"
)]
const fn kind(problem: &DecodeProblem) -> &'static str {
    match problem {
        DecodeProblem::NotJson { bytes: _, html: _ } => "not_json",
        DecodeProblem::NotUtf8 { bytes: _ } => "not_utf8",
        DecodeProblem::Mismatch {
            found: _,
            expected: _,
        } => "mismatch",
        DecodeProblem::Missing { field: _ } => "missing",
        DecodeProblem::MissingPointer { pointer: _ } => "missing_pointer",
        DecodeProblem::Length {
            expected: _,
            got: _,
        } => "length",
        _ => "other",
    }
}
