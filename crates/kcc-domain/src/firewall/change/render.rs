//! Complete CLI rendering from catalog-validated firewall requests.
#![expect(
    clippy::missing_errors_doc,
    reason = "workflow request rendering is not an inline candidate"
)]
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private token renderers are narrowly named"
    )
)]

use alloc::{format, vec};

use kcc_app::workflow::{CliChangeRequest, CliCommand as ValidatedCli};
use kcc_catalog::ValidatedRequest;
use serde_json::{Value, json};

use super::verify::{OwnedRuleProperty, Verification};
use crate::{ChangeOp, DomainError, Result, cli_token, verification as readback};

/// Converts a validated firewall operation into protected CLI workflow input.
pub(super) fn request(
    operation: &ChangeOp,
    verification: &Verification,
) -> Result<CliChangeRequest> {
    let line = line(operation, verification)?;
    let validated = operation
        .requests
        .last()
        .ok_or(DomainError::InvalidResponse)?;
    readback::complete(CliChangeRequest::new(
        vec![ValidatedCli::new(line, validated.clone())],
        Vec::new(),
        operation.permission,
        json!({"domain":"firewall"}),
    ))
}

fn line(operation: &ChangeOp, verification: &Verification) -> Result<String> {
    let [context, leaf] = operation.requests.as_slice() else {
        return Err(DomainError::InvalidResponse);
    };
    let name = text(context, "name")?;
    let mut words = if context.path == "interface" {
        vec![
            "interface".to_owned(),
            name.to_owned(),
            "ip".to_owned(),
            "access-group".to_owned(),
        ]
    } else {
        vec![
            "access-list".to_owned(),
            name.to_owned(),
            leaf.path
                .strip_prefix("access-list ")
                .ok_or(DomainError::InvalidResponse)?
                .to_owned(),
        ]
    };
    match leaf.path.as_str() {
        "access-list permit" | "access-list deny" => {
            render_rule(&mut words, leaf, verification.protocol()?)?;
        }
        "access-list rule" => render_property(&mut words, leaf, verification.property()?)?,
        "interface ip access-group" => {
            words.extend([
                text(leaf, "acl")?.to_owned(),
                text(leaf, "direction")?.to_owned(),
            ]);
        }
        _ => return Err(DomainError::InvalidResponse),
    }
    let positive = words.join(" ");
    Ok(if leaf.value().get("no") == Some(&Value::Bool(true)) {
        format!("no {positive}")
    } else {
        positive
    })
}

fn render_rule(words: &mut Vec<String>, request: &ValidatedRequest, protocol: &str) -> Result<()> {
    words.extend([
        protocol.to_owned(),
        text(request, "source")?.to_owned(),
        text(request, "source-mask")?.to_owned(),
    ]);
    render_port(words, request, "source")?;
    words.extend([
        text(request, "destination")?.to_owned(),
        text(request, "destination-mask")?.to_owned(),
    ]);
    render_port(words, request, "destination")
}

fn render_port(words: &mut Vec<String>, request: &ValidatedRequest, side: &str) -> Result<()> {
    let (port, end, operator) = match side {
        "source" => ("source-port", "source-end-port", "src-port-operator"),
        "destination" => (
            "destination-port",
            "destination-end-port",
            "dst-port-operator",
        ),
        _ => return Err(DomainError::InvalidResponse),
    };
    match (number(request, port), number(request, end)) {
        (None, None) => Ok(()),
        (Some(value), None) if text(request, operator)? == "eq" => {
            words.extend(["port".to_owned(), "eq".to_owned(), value.to_string()]);
            Ok(())
        }
        (Some(first), Some(last)) => {
            words.extend([
                "port".to_owned(),
                "range".to_owned(),
                first.to_string(),
                last.to_string(),
            ]);
            Ok(())
        }
        (None, Some(_)) | (Some(_), None) => Err(DomainError::InvalidResponse),
    }
}

fn render_property(
    words: &mut Vec<String>,
    request: &ValidatedRequest,
    property: &OwnedRuleProperty,
) -> Result<()> {
    words.push(
        number(request, "index")
            .ok_or(DomainError::InvalidResponse)?
            .to_string(),
    );
    let (property_words, negated) = match property {
        OwnedRuleProperty::Description(Some(value)) => (
            vec!["description".to_owned(), cli_token::quoted_text(value)?],
            false,
        ),
        OwnedRuleProperty::Description(None) => (vec!["description".to_owned()], true),
        OwnedRuleProperty::Schedule(Some(value)) => {
            (vec!["schedule".to_owned(), value.clone()], false)
        }
        OwnedRuleProperty::Schedule(None) => (vec!["schedule".to_owned()], true),
        OwnedRuleProperty::Disable(disabled) => (vec!["disable".to_owned()], !disabled),
        OwnedRuleProperty::Order(position) => {
            (vec!["order".to_owned(), position.to_string()], false)
        }
    };
    if negated != (request.value().get("no") == Some(&Value::Bool(true))) {
        return Err(DomainError::InvalidResponse);
    }
    words.extend(property_words);
    Ok(())
}

fn text<'request>(request: &'request ValidatedRequest, field: &str) -> Result<&'request str> {
    request
        .value()
        .get(field)
        .and_then(Value::as_str)
        .ok_or(DomainError::InvalidResponse)
}

fn number(request: &ValidatedRequest, field: &str) -> Option<u64> {
    request.value().get(field).and_then(Value::as_u64)
}
