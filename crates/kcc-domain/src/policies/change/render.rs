//! Rendering of previously catalog-validated connection-policy requests.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "workflow request rendering is not an inline candidate"
)]
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private token renderers are named after their validated policy command shape"
    )
)]

use alloc::{format, vec};

use kcc_app::workflow::{CliChangeRequest, CliCommand as ValidatedCli};
use kcc_catalog::ValidatedRequest;
use serde_json::{Value, json};

use crate::{ChangeOp, DomainError, Result, verification};

/// Converts a connection-policy plan into protected CLI workflow input.
pub fn request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let context = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let name = text(context, "name")?;
    let command = match operation.requests.as_slice() {
        [only] => ValidatedCli::new(context_line(only, name), only.clone()),
        [_, leaf] => ValidatedCli::new(leaf_line(name, leaf)?, leaf.clone()),
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
pub(super) fn expected_leaf(request: &ValidatedRequest) -> Result<Vec<String>> {
    let mut tokens = match request.path.as_str() {
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
    if request.value().get("no") == Some(&Value::Bool(true)) {
        tokens.insert(0, "no".to_owned());
    }
    Ok(tokens)
}

fn context_line(request: &ValidatedRequest, name: &str) -> String {
    if request.value().get("no") == Some(&Value::Bool(true)) {
        format!("no ip policy {name}")
    } else {
        format!("ip policy {name}")
    }
}

fn leaf_line(name: &str, request: &ValidatedRequest) -> Result<String> {
    let mut tokens = expected_leaf(request)?;
    let negated = tokens.first().is_some_and(|word| word == "no");
    if negated {
        drop(tokens.remove(0));
    }
    let line = format!("ip policy {name} {}", tokens.join(" "));
    Ok(if negated { format!("no {line}") } else { line })
}

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

fn text<'request>(request: &'request ValidatedRequest, field: &str) -> Result<&'request str> {
    optional_text(request, field).ok_or(DomainError::InvalidResponse)
}

fn optional_text<'request>(
    request: &'request ValidatedRequest,
    field: &str,
) -> Option<&'request str> {
    request.value().get(field).and_then(Value::as_str)
}

fn number(request: &ValidatedRequest, field: &str) -> Option<u64> {
    request.value().get(field).and_then(Value::as_u64)
}
