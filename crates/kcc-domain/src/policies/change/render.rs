//! Rendering of previously catalog-validated connection-policy requests.

use alloc::{format, vec};

use kcc_app::workflow::{CliChangeRequest, CliCommand as ValidatedCli};
use kcc_catalog::ValidatedRequest;
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainError, Result, cli_token,
    request_words::{number, optional_text, text},
    verification,
};

/// Converts a connection-policy plan into protected CLI workflow input.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
#[inline]
pub fn request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let context = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let name = text(context, "name")?;
    let command = match operation.requests.as_slice() {
        [only] => ValidatedCli::new(context_line(only, name), only.clone())?,
        [_, leaf] => ValidatedCli::new(leaf_line(name, leaf)?, leaf.clone())?,
        _ => return Err(DomainError::InvalidResponse),
    };
    verification::complete(CliChangeRequest::new(
        vec![command],
        Vec::new(),
        operation.permission,
        json!({"domain":"policies","name":name}),
    ))
}

/// Returns the positive leaf tokens expected in a fresh running-config read.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
pub(super) fn expected_leaf(request: &ValidatedRequest) -> Result<Vec<String>> {
    let mut tokens = match request.path.as_str() {
        "ip policy description" if is_removal(request) => vec!["description".to_owned()],
        "ip policy description" => vec![
            "description".to_owned(),
            text(request, "description")?.to_owned(),
        ],
        "ip policy permit" => {
            let mut words = vec![
                "permit".to_owned(),
                "global".to_owned(),
                text(request, "interface")?.to_owned(),
            ];
            if let Some(order) = number(request, "order") {
                words.extend(["order".to_owned(), order.to_string()]);
            }
            words
        }
        "ip policy multipath" => vec!["multipath".to_owned()],
        "ip policy route" => route_tokens(request)?,
        "ip policy rate-limit input" | "ip policy rate-limit output" => rate_tokens(request)?,
        "ip policy standalone" => vec!["standalone".to_owned()],
        _ => return Err(DomainError::InvalidResponse),
    };
    if is_removal(request) {
        tokens.insert(0, "no".to_owned());
    }
    Ok(tokens)
}

/// Whether `request` removes its setting (`"no": true`).
fn is_removal(request: &ValidatedRequest) -> bool {
    request.value().get("no") == Some(&Value::Bool(true))
}

/// The `ip policy <name>` context line, or its removal.
fn context_line(request: &ValidatedRequest, name: &str) -> String {
    if is_removal(request) {
        format!("no ip policy {name}")
    } else {
        format!("ip policy {name}")
    }
}

/// The CLI line of one policy leaf request under the policy `name`.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when the request is missing a field it
/// renders, and [`DomainError::InvalidCliToken`] when a description cannot be quoted.
fn leaf_line(name: &str, request: &ValidatedRequest) -> Result<String> {
    let mut tokens = expected_leaf(request)?;
    let negated = tokens.first().is_some_and(|word| word == "no");
    if negated {
        drop(tokens.remove(0));
    }
    if let [keyword, description] = tokens.as_mut_slice()
        && keyword == "description"
    {
        *description = cli_token::quoted_text(description)?;
    }
    let line = format!("ip policy {name} {}", tokens.join(" "));
    Ok(if negated { format!("no {line}") } else { line })
}

/// The words of a policy route request.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when a required field is missing.
fn route_tokens(request: &ValidatedRequest) -> Result<Vec<String>> {
    let mut words = vec!["route".to_owned()];
    if let Some(network) = optional_text(request, "network") {
        words.extend([network.to_owned(), text(request, "mask")?.to_owned()]);
    } else {
        words.push(text(request, "host")?.to_owned());
    }
    if let Some(gateway) = optional_text(request, "gateway") {
        words.push(gateway.to_owned());
    } else {
        words.push(text(request, "interface")?.to_owned());
    }
    if let Some(metric) = number(request, "metric") {
        words.push(metric.to_string());
    }
    Ok(words)
}

/// The words of a policy rate-limit request.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when the path has no direction or the
/// interface is missing.
fn rate_tokens(request: &ValidatedRequest) -> Result<Vec<String>> {
    let direction = request
        .path
        .strip_prefix("ip policy rate-limit ")
        .ok_or(DomainError::InvalidResponse)?;
    Ok(vec![
        "rate-limit".to_owned(),
        text(request, "interface")?.to_owned(),
        direction.to_owned(),
        number(request, "rate").map_or_else(|| "auto".to_owned(), |rate| rate.to_string()),
    ])
}
