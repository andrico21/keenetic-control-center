//! Non-secret collection matching for fresh read-back expectations.

use core::str::from_utf8;

use kcc_config::config_text::{Node, Token, parse};
use kcc_rci::{ConfigKind, RciClient};
use secrecy::ExposeSecret as _;
use serde_json::Value;
use zeroize::Zeroize as _;

use super::{PresencePredicate, VerificationSpec, WorkflowError};

/// Compares a non-secret command against a fresh canonical running configuration.
// cancel-safe: only downloads and decodes router state.
pub(super) async fn configuration(
    client: &RciClient,
    spec: &VerificationSpec,
) -> Result<(), WorkflowError> {
    let bytes = client.download_config(ConfigKind::Running).await?;
    let text = from_utf8(bytes.expose_secret()).map_err(|_error| WorkflowError::InvalidResponse)?;
    if spec.predicate == Some(PresencePredicate::ConfigSecret) {
        return credential(text, spec);
    }
    let expected = spec
        .expected
        .as_array()
        .ok_or(WorkflowError::InvalidResponse)?;
    let mut ast = parse(text).map_err(|_error| WorkflowError::InvalidResponse)?;
    let present = command_present(&ast.nodes, expected);
    wipe_tokens(&mut ast.nodes);
    let wanted = spec.predicate == Some(PresencePredicate::ConfigCommand);
    if present != wanted {
        return Err(WorkflowError::VerificationFailed {
            field: spec.field.clone(),
        });
    }
    Ok(())
}

/// Matches context tokens by borrowing the parsed tree without copying credentials.
fn command_present(nodes: &[Node], expected: &[Value]) -> bool {
    nodes.iter().any(|node| {
        let length = node.tokens.len().min(expected.len());
        let prefix_matches = node.tokens.iter().zip(expected).all(|(token, word)| {
            matches!(token, Token::Word(actual_word) if word.as_str() == Some(actual_word.as_str()))
        });
        prefix_matches
            && (expected.len() <= node.tokens.len()
                || expected
                    .get(length..)
                    .is_some_and(|remaining| command_present(&node.children, remaining)))
    })
}

/// Erases parsed configuration tokens before their ordinary string allocations are dropped.
fn wipe_tokens(nodes: &mut [Node]) {
    for node in nodes {
        for token in &mut node.tokens {
            match token {
                Token::Word(word) | Token::Ns3(word) => word.zeroize(),
                _ => {}
            }
        }
        wipe_tokens(&mut node.children);
    }
}

/// Checks a credential payload without allocating or comparing its value.
fn credential(text: &str, spec: &VerificationSpec) -> Result<(), WorkflowError> {
    let prefix = spec
        .expected
        .as_str()
        .ok_or(WorkflowError::InvalidResponse)?;
    let mut contexts = Vec::<(usize, &str)>::new();
    let present = text.lines().any(|line| {
        let trimmed = line.trim_start();
        if trimmed.starts_with('!') || trimmed.is_empty() {
            return false;
        }
        let indent = line.len().saturating_sub(trimmed.len());
        contexts.retain(|(depth, _)| *depth < indent);
        let remaining = contexts.iter().try_fold(prefix, |rest, (_, context)| {
            rest.strip_prefix(context)?.strip_prefix(' ')
        });
        let found = remaining
            .and_then(|rest| trimmed.strip_prefix(rest))
            .and_then(|tail| tail.strip_prefix(' '))
            .map(|payload| payload.strip_prefix("ns3 ").unwrap_or(payload))
            .is_some_and(|payload| !payload.is_empty() && payload.len() <= 512);
        contexts.push((indent, trimmed));
        found
    });
    if !present {
        return Err(WorkflowError::VerificationFailed {
            field: spec.field.clone(),
        });
    }
    Ok(())
}

/// Compares requested fields while allowing unrelated router-owned fields.
pub(super) fn contains(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::Object(fields), Value::Object(wanted)) => wanted
            .iter()
            .all(|(key, value)| fields.get(key).is_some_and(|found| contains(found, value))),
        (Value::Array(items), Value::Array(wanted)) => wanted
            .iter()
            .all(|value| items.iter().any(|found| contains(found, value))),
        _ => actual == expected,
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions report regressions"
)]
mod tests {
    use serde_json::json;

    use super::contains;

    /// Matching must compare each intended field rather than merely find a row.
    #[test]
    fn named_row_requires_every_requested_field() {
        let actual = json!({"name":"http","enabled":true,"port":8_080_u16});
        assert!(contains(&actual, &json!({"name":"http","enabled":true})));
        assert!(!contains(&actual, &json!({"name":"ssh","enabled":true})));
        assert!(!contains(&actual, &json!({"name":"http","enabled":false})));
        assert!(!contains(&actual, &json!({"security-level":"private"})));
    }
}
