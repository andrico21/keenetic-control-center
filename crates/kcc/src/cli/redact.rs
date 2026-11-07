//! Configuration text without its secrets, as the Web UI's redacted download.

use kcc_config::{
    config_text::{Ast, Node, Token, flatten, parse, print},
    secrets::redact,
};

use super::exit::{Exit, Failure, Outcome};

/// What a removed secret shows.
const REDACTED: &str = "<redacted>";

/// `text` with every registered secret and every `ns3` blob replaced, marked as redacted
/// and without the router checksum that no longer matches it.
///
/// # Errors
///
/// Returns a validation failure when `text` is not a configuration.
pub(crate) fn redacted_copy(text: &str) -> Outcome<String> {
    let mut copy = redacted(text)?;
    copy.header.md5 = None;
    drop(
        copy.header
            .extra
            .insert("kcc-redacted".to_owned(), "true".to_owned()),
    );
    Ok(print(&copy))
}

/// The flattened commands of `text` with secrets replaced.
///
/// # Errors
///
/// Returns a validation failure when `text` is not a configuration.
pub(crate) fn redacted_lines(text: &str) -> Outcome<Vec<String>> {
    Ok(flatten(&redacted(text)?)
        .iter()
        .map(ToString::to_string)
        .collect())
}

/// Parses `text` and replaces its secrets.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
fn redacted(text: &str) -> Outcome<Ast> {
    let ast = parse(text).map_err(|error| Failure::text(Exit::Validation, &error))?;
    let mut copy = redact(&ast);
    mask(&mut copy.nodes);
    Ok(copy)
}

/// Replaces every `ns3` token below `nodes`, registered secret or not.
fn mask(nodes: &mut [Node]) {
    for node in nodes {
        for token in &mut node.tokens {
            if matches!(token, Token::Ns3(_)) {
                *token = Token::Word(REDACTED.to_owned());
            }
        }
        mask(&mut node.children);
    }
}
