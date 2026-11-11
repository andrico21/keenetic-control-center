//! Protected connection-policy execution with fresh read-back verification.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "protected policy execution is not an inline candidate"
)]
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "the private read-back decoder is named after its policy verification role"
    )
)]

use kcc_app::workflow::{ChangeSet, CliChangeResult};
use serde_json::{Value, json};

use super::render;
use crate::{ChangeOp, DomainError, Result, RouterCtx};

/// Applies a policy plan and verifies it against a fresh `show rc` read.
// NOT cancel-safe: cancelled after the CLI request is sent, the router stays changed
// and the read-back verification never runs.
pub async fn apply(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    operation: &ChangeOp,
) -> Result<CliChangeResult> {
    let context = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let name = context
        .value
        .get("name")
        .and_then(Value::as_str)
        .ok_or(DomainError::InvalidResponse)?;
    let result = changes.apply_cli(render::request(operation)?).await?;
    let commands = policy_commands(router, name).await?;
    let verified = match operation.requests.as_slice() {
        [only] if only.value.get("no") == Some(&Value::Bool(true)) => commands.is_none(),
        [_] => commands.is_some(),
        [_, leaf] => {
            let expected = render::expected_leaf(leaf)?;
            let negated = expected.first().is_some_and(|word| word == "no");
            let positive = if negated {
                expected.get(1..).ok_or(DomainError::InvalidResponse)?
            } else {
                expected.as_slice()
            };
            commands.is_some_and(|rows| rows.iter().any(|row| row == positive) != negated)
        }
        _ => false,
    };
    if !verified {
        return Err(DomainError::InvalidResponse);
    }
    Ok(result)
}

async fn policy_commands(router: &RouterCtx, name: &str) -> Result<Option<Vec<Vec<String>>>> {
    let response = router.client.show_rc(json!({"ip":{"policy":{}}})).await?;
    response
        .configuration_tree()
        .pointer("/ip/policy")
        .and_then(|value| value.get(name))
        .map(|value| match value {
            Value::Array(rows) => rows
                .iter()
                .map(|row| match row {
                    Value::Array(words) => words
                        .iter()
                        .map(|word| {
                            word.as_str()
                                .map(ToOwned::to_owned)
                                .ok_or(DomainError::InvalidResponse)
                        })
                        .collect(),
                    Value::Object(fields) => fields
                        .get("command")
                        .and_then(Value::as_array)
                        .ok_or(DomainError::InvalidResponse)?
                        .iter()
                        .map(|word| {
                            word.as_str()
                                .map(ToOwned::to_owned)
                                .ok_or(DomainError::InvalidResponse)
                        })
                        .collect(),
                    Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                        Err(DomainError::InvalidResponse)
                    }
                })
                .collect(),
            Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_)
            | Value::Object(_) => Err(DomainError::InvalidResponse),
        })
        .transpose()
}
