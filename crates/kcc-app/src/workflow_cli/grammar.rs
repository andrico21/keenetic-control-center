//! Catalog synopsis matching for protected command templates.

use core::slice;

use kcc_catalog::{
    ArgumentKind, Catalog, HttpMethod, SecretValue, ValidatedRequest, generated::FILES,
};
use kcc_rci::version::FirmwareVersion;
use serde::Deserialize;
use serde_json::{Value, json};

use super::command::SecretCommandError;

/// Generated synopsis nodes, including explicit alternatives and optional argument slots.
#[derive(Deserialize)]
#[serde(tag = "node", content = "value")]
enum Grammar {
    /// Ordered words.
    Sequence(Vec<Self>),
    /// Optional word or group.
    Optional(Box<Self>),
    /// Parenthesized group or manual CLI context marker.
    Group(Box<Self>),
    /// One of the documented forms.
    Alternative(Vec<Self>),
    /// Named, typed argument.
    Argument(String),
    /// Exact literal.
    Keyword(String),
}

/// One embedded command's retained source grammar.
#[derive(Deserialize)]
struct Definition {
    /// Catalog command path.
    path: String,
    /// Generated positional grammar.
    synopsis: Option<Grammar>,
}

/// A generated shard; unrelated metadata is decoded by the catalog itself.
#[derive(Deserialize)]
struct Shard {
    /// Firmware line.
    version: String,
    /// Commands sharing a root keyword.
    commands: Vec<Definition>,
}

/// Checks every declaring firmware line because legacy requests retain no catalog identity.
///
/// # Errors
/// Refuses absent, ambiguous, or malformed metadata and templates outside its grammar.
pub(super) fn validate_grammar(
    request: &ValidatedRequest,
    template: &str,
) -> Result<(), SecretCommandError> {
    let root = request
        .path
        .split_whitespace()
        .next()
        .ok_or(SecretCommandError::Template)?;
    let suffix = format!("/{root}.json");
    let tokens = template.split_whitespace().collect::<Vec<_>>();
    let mut found = false;
    for (_, contents) in FILES.iter().filter(|(file, _)| file.ends_with(&suffix)) {
        let shard: Shard =
            serde_json::from_str(contents).map_err(|_error| SecretCommandError::Template)?;
        if !shard
            .commands
            .iter()
            .any(|entry| entry.path == request.path)
        {
            continue;
        }
        found = true;
        let firmware = FirmwareVersion::from_title(&format!("{}.0", shard.version))
            .map_err(|_error| SecretCommandError::Template)?;
        let catalog = Catalog::for_firmware_and_model(firmware, None)
            .map_err(|_error| SecretCommandError::Template)?;
        let forms =
            command_forms(&shard.commands, &request.path).ok_or(SecretCommandError::Template)?;
        let matches = |((path, node), token): (&(&str, &Grammar), &&str)| match node {
            Grammar::Keyword(word) => word == token,
            Grammar::Argument(name) => {
                let Some(argument) = catalog
                    .lookup(path)
                    .and_then(|command| command.arguments.get(name))
                else {
                    return false;
                };
                let pointer = format!("/{}", name.replace('~', "~0").replace('/', "~1"));
                let secret = *path == request.path
                    && request
                        .protected_value()
                        .secret_pointers()
                        .any(|slot| slot == pointer);
                if token.starts_with('{') || secret {
                    return secret
                        && **token == format!("{{{pointer}}}")
                        && (argument.kind == ArgumentKind::Password
                            || SecretValue::new(path, json!({name: "classification-probe"}))
                                .has_secrets());
                }
                if !token.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'-' | b'_' | b'.' | b'/' | b'+' | b'=' | b'@' | b':')
                }) {
                    return false;
                }
                let value = match argument.kind {
                    ArgumentKind::Integer => token.parse::<i64>().map_or(Value::Null, Value::from),
                    _ => Value::String((*token).to_owned()),
                };
                catalog
                    .validate(path, HttpMethod::Post, &json!({name: value}))
                    .is_ok()
            }
            Grammar::Sequence(_)
            | Grammar::Optional(_)
            | Grammar::Group(_)
            | Grammar::Alternative(_) => false,
        };
        if !forms
            .iter()
            .any(|form| form.len() == tokens.len() && form.iter().zip(&tokens).all(matches))
        {
            return Err(SecretCommandError::Template);
        }
    }
    found.then_some(()).ok_or(SecretCommandError::Template)
}

/// Expands a positive command form and recursively supplies omitted parent contexts.
fn command_forms<'defs>(
    definitions: &'defs [Definition],
    path: &str,
) -> Option<Vec<Vec<(&'defs str, &'defs Grammar)>>> {
    let definition = definitions.iter().find(|entry| entry.path == path)?;
    let synopsis = definition.synopsis.as_ref()?;
    let nodes = match synopsis {
        Grammar::Sequence(nodes) => nodes.as_slice(),
        _ => slice::from_ref(synopsis),
    };
    let positive = nodes.iter().take_while(|node| !matches!(node, Grammar::Group(inner) if matches!(inner.as_ref(), Grammar::Keyword(word) if word.starts_with("config")))).collect::<Vec<_>>();
    let leading = positive
        .iter()
        .map_while(|node| match node {
            Grammar::Keyword(word) => Some(word.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(" ");
    if leading.is_empty() {
        return None;
    }
    let parent = path.strip_suffix(&leading)?.trim_end();
    let parents = if parent.is_empty() {
        vec![Vec::new()]
    } else {
        command_forms(definitions, parent)?
    };
    let forms = expand_sequence(&positive);
    Some(
        parents
            .iter()
            .flat_map(|parent_form| {
                forms.iter().map(|form| {
                    parent_form
                        .iter()
                        .copied()
                        .chain(form.iter().map(|node| (definition.path.as_str(), *node)))
                        .collect()
                })
            })
            .collect(),
    )
}

/// Expands finite generated syntax without inventing any argument order.
fn expand(node: &Grammar) -> Vec<Vec<&Grammar>> {
    match node {
        Grammar::Keyword(_) | Grammar::Argument(_) => vec![vec![node]],
        Grammar::Group(inner) => expand(inner),
        Grammar::Optional(inner) => {
            let mut forms = expand(inner);
            forms.push(Vec::new());
            forms
        }
        Grammar::Alternative(nodes) => nodes.iter().flat_map(expand).collect(),
        Grammar::Sequence(nodes) => expand_sequence(&nodes.iter().collect::<Vec<_>>()),
    }
}

/// Combines ordered syntax alternatives for both root forms and nested sequences.
fn expand_sequence<'node>(nodes: &[&'node Grammar]) -> Vec<Vec<&'node Grammar>> {
    nodes.iter().fold(vec![Vec::new()], |forms, child| {
        let alternatives = expand(child);
        forms
            .iter()
            .flat_map(|form| {
                alternatives
                    .iter()
                    .map(|alternative| form.iter().chain(alternative).copied().collect())
            })
            .collect()
    })
}
