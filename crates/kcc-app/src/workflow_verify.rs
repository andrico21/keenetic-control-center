//! Read-back of applied changes: fresh router reads compared without secret material.

use core::str::from_utf8;

use kcc_config::config_text::{Node, Token, parse};
use kcc_rci::{ConfigKind, RciBody, RciClient, RciError, RciPath};
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use zeroize::Zeroize as _;

use super::{PresencePredicate, VerificationSpec, WorkflowError};

/// Executes one read-back expectation.
// cancel-safe: only reads router state.
pub(super) async fn verify(
    client: &RciClient,
    spec: &VerificationSpec,
) -> Result<(), WorkflowError> {
    let satisfied = match spec.predicate {
        Some(
            PresencePredicate::ConfigCommand
            | PresencePredicate::ConfigCommandAbsent
            | PresencePredicate::ConfigSecret,
        ) => return configuration(client, spec).await,
        None => Readback::fetch(client, spec).await?.field() == Some(&spec.expected),
        Some(PresencePredicate::Absent) => Readback::fetch(client, spec).await?.field_absent(),
        Some(PresencePredicate::Contains) => Readback::fetch(client, spec)
            .await?
            .rows()
            .is_some_and(|rows| rows.iter().any(|row| contains(row, &spec.expected))),
        Some(PresencePredicate::Excludes) => Readback::fetch(client, spec)
            .await?
            .rows()
            .is_some_and(|rows| !rows.iter().any(|row| contains(row, &spec.expected))),
        Some(PresencePredicate::Present) => Readback::fetch(client, spec)
            .await?
            .field()
            .is_some_and(|value| !value.is_null()),
        Some(PresencePredicate::NonEmpty) => Readback::fetch(client, spec)
            .await?
            .text()
            .is_some_and(|text| !text.is_empty()),
        Some(PresencePredicate::LengthRange { minimum, maximum }) => Readback::fetch(client, spec)
            .await?
            .text()
            .is_some_and(|text| (minimum..=maximum).contains(&text.len())),
        Some(PresencePredicate::MarkerOrLengthRange { minimum, maximum }) => {
            let readback = Readback::fetch(client, spec).await?;
            readback.field() == Some(&Value::Bool(true))
                || readback
                    .text()
                    .is_some_and(|text| (minimum..=maximum).contains(&text.len()))
        }
    };
    if !satisfied {
        return Err(WorkflowError::VerificationFailed {
            field: if spec.field.is_empty() {
                spec.path.join("/")
            } else {
                spec.field.clone()
            },
        });
    }
    Ok(())
}

/// One fresh read of a verification's resource.
struct Readback<'spec> {
    /// The expectation the read serves.
    spec: &'spec VerificationSpec,
    /// Whether the resource is a `show rc` configuration subtree.
    configuration: bool,
    /// The decoded router answer.
    actual: Value,
}

impl<'spec> Readback<'spec> {
    /// Reads the resource named by `spec.path`.
    // cancel-safe: only reads router state.
    async fn fetch(
        client: &RciClient,
        spec: &'spec VerificationSpec,
    ) -> Result<Self, WorkflowError> {
        let path = RciPath::from_segments(&spec.path).map_err(|_error| RciError::Validation)?;
        let configuration = spec.path.starts_with(&["show".to_owned(), "rc".to_owned()]);
        let actual = if configuration {
            let tree = spec
                .path
                .iter()
                .skip(2)
                .rev()
                .fold(json!({}), |child, segment| json!({segment:child}));
            client.show_rc(tree).await?.configuration_tree().clone()
        } else {
            let RciBody::Json(response) = client.show(&path, &()).await? else {
                return Err(WorkflowError::VerificationFailed {
                    field: spec.field.clone(),
                });
            };
            response.value
        };
        Ok(Self {
            spec,
            configuration,
            actual,
        })
    }

    /// The configuration subtree, or the whole answer of an ordinary read.
    fn selected(&self) -> Option<&Value> {
        if self.configuration {
            self.spec
                .path
                .iter()
                .skip(2)
                .try_fold(&self.actual, |parent, segment| parent.get(segment))
        } else {
            Some(&self.actual)
        }
    }

    /// The expected field, inside the named collection row when the spec names one.
    fn field(&self) -> Option<&Value> {
        let row = match &self.spec.row {
            Some((key, expected)) => self
                .selected()
                .and_then(Value::as_array)
                .and_then(|rows| rows.iter().find(|row| row.get(key) == Some(expected))),
            None => self.selected(),
        }?;
        row.pointer(&self.spec.field)
    }

    /// The expected field as a collection.
    fn rows(&self) -> Option<&Vec<Value>> {
        self.field().and_then(Value::as_array)
    }

    /// The expected field as a string.
    fn text(&self) -> Option<&str> {
        self.field().and_then(Value::as_str)
    }

    /// The field is missing from an object the router did return.
    fn field_absent(&self) -> bool {
        self.spec.field.rsplit_once('/').is_some_and(|(parent, _)| {
            self.selected()
                .and_then(|value| value.pointer(parent))
                .is_some_and(Value::is_object)
        }) && self.field().is_none()
    }
}

/// Compares a non-secret command against a fresh canonical running configuration.
// cancel-safe: only downloads and decodes router state.
async fn configuration(client: &RciClient, spec: &VerificationSpec) -> Result<(), WorkflowError> {
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
fn contains(actual: &Value, expected: &Value) -> bool {
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
