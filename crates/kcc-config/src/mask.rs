//! The one owner of secret masking: secret-named members of JSON answers and the secrets
//! in configuration text.
//!
//! [`mask_json`] replaces every member whose name [`is_secret_name`] recognizes, whatever
//! it holds, with the caller's marker. [`redact_text`] and [`redacted_config`] replace
//! every secret the registry in [`crate::secrets`] knows, and every `ns3` payload, with
//! `<redacted>`.

use serde_json::Value;

use crate::{
    config_text::{Ast, CliLine, Node, ParseError, Token, parse, print},
    secrets::{REDACTED, redact, redact_path},
};

/// The header field that marks a configuration copy whose secrets kcc removed; such a
/// copy is never accepted as a configuration again.
pub const REDACTED_MARK: &str = "kcc-redacted";

/// Parts that make any member name a secret, after normalization.
const SECRET_PARTS: [&str; 10] = [
    "password",
    "passwd",
    "passphrase",
    "token",
    "secret",
    "api_key",
    "private_key",
    "ns3",
    "psk",
    "preshared",
];

/// Whole member names that are secrets, after normalization.
const SECRET_NAMES: [&str; 3] = ["key", "pin", "community"];

/// Whether a member or argument named `name` holds a secret.
///
/// Case is ignored and `-` counts as `_`. A name is a secret when it is `key`, `pin` or
/// `community`, ends in `_key`, or contains `password`, `passwd`, `passphrase`, `token`,
/// `secret`, `api_key`, `private_key`, `ns3`, `psk` or `preshared`.
#[must_use]
#[inline]
pub fn is_secret_name(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase().replace('-', "_");
    SECRET_NAMES.contains(&normalized.as_str())
        || normalized.ends_with("_key")
        || SECRET_PARTS.iter().any(|part| normalized.contains(part))
}

/// Replaces every member of `value` whose name is a secret ([`is_secret_name`]) with the
/// string `marker`, whatever the member holds: a scalar, an object or an array.
#[inline]
#[expect(
    clippy::module_name_repetitions,
    reason = "callers import it unqualified next to `redact_text`; `json` names the input"
)]
pub fn mask_json(value: &mut Value, marker: &str) {
    match value {
        Value::Object(object) => {
            for (name, member) in object.iter_mut() {
                if is_secret_name(name) {
                    *member = Value::String(marker.to_owned());
                } else {
                    mask_json(member, marker);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|item| mask_json(item, marker)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// `text`, configuration text or any run of its lines, with every registered secret and
/// every `ns3` payload replaced by `<redacted>`.
///
/// Each line is matched together with the block lines above it, so an indented line is
/// redacted inside its block and a lone line on its own. A line holding no secret is
/// kept byte for byte, as are comments, header lines and line endings. A line that
/// cannot be read keeps only its indentation and `<redacted>`.
#[must_use]
#[inline]
pub fn redact_text(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut blocks = Vec::new();
    for line in text.split_inclusive('\n') {
        let content = line.trim_end_matches(['\n', '\r']);
        output.push_str(&redact_line(content, &mut blocks));
        output.push_str(line.strip_prefix(content).unwrap_or_default());
    }
    output
}

/// One line of [`redact_text`], given the open blocks above it as indentation and words.
fn redact_line(line: &str, blocks: &mut Vec<(usize, Vec<Token>)>) -> String {
    let command = line.trim_start();
    if command.is_empty() || command.starts_with('!') {
        return line.to_owned();
    }
    let indent = line.strip_suffix(command).unwrap_or_default();
    while blocks
        .last()
        .is_some_and(|(depth, _)| *depth >= indent.len())
    {
        drop(blocks.pop());
    }
    let Some(own) = parse(command)
        .ok()
        .and_then(|ast| ast.nodes.into_iter().next())
        .map(|node| node.tokens)
    else {
        blocks.push((indent.len(), Vec::new()));
        return format!("{indent}{REDACTED}");
    };
    let mut path: Vec<Token> = blocks
        .iter()
        .flat_map(|(_, tokens)| tokens.iter().cloned())
        .chain(own.iter().cloned())
        .collect();
    redact_path(&mut path);
    let mut shown = path.split_off(path.len().saturating_sub(own.len()));
    plain_marker(&mut shown);
    let unchanged = shown == own;
    blocks.push((indent.len(), own));
    if unchanged {
        line.to_owned()
    } else {
        let shown_line = CliLine {
            tokens: shown,
            line_no: 0,
        };
        format!("{indent}{shown_line}")
    }
}

/// `ast` as kcc shows a configuration: every registered secret and every `ns3` payload
/// replaced, each `ns3` token shown as the bare `<redacted>` word.
#[must_use]
#[inline]
pub fn redacted_config(ast: &Ast) -> Ast {
    let mut copy = redact(ast);
    plain_nodes(&mut copy.nodes);
    copy
}

/// The copy of `text` to hand out without its secrets: canonical text marked with
/// [`REDACTED_MARK`], without the router's checksum, which no longer matches it.
///
/// # Errors
///
/// Returns why `text` is not a configuration; no copy is made then.
#[inline]
pub fn redacted_copy(text: &str) -> Result<String, ParseError> {
    let mut copy = redacted_config(&parse(text)?);
    copy.header.md5 = None;
    drop(
        copy.header
            .extra
            .insert(REDACTED_MARK.to_owned(), "true".to_owned()),
    );
    Ok(print(&copy))
}

/// Shows every `ns3` token below `nodes` as the bare marker.
fn plain_nodes(nodes: &mut [Node]) {
    for node in nodes {
        plain_marker(&mut node.tokens);
        plain_nodes(&mut node.children);
    }
}

/// Shows every `ns3` token of `tokens` as the bare marker.
fn plain_marker(tokens: &mut [Token]) {
    for token in tokens {
        if matches!(token, Token::Ns3(_)) {
            *token = Token::Word(REDACTED.to_owned());
        }
    }
}

#[cfg(test)]
#[path = "mask_tests.rs"]
mod tests;
