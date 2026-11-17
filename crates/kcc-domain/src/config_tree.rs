//! Lookups in configuration text parsed by `kcc_config::config_text`.
//!
//! Commands are compared as the parser reads them: a context or child written as a string
//! is parsed by the same tokenizer, so quoting and spacing are compared canonically.

use kcc_config::config_text::{Ast, Node, Token, parse};

/// The words of the single command `line`; empty when `line` is not exactly one command.
pub(crate) fn command(line: &str) -> Vec<Token> {
    parse(line)
        .ok()
        .and_then(|ast| match ast.nodes.as_slice() {
            [node] if node.children.is_empty() => Some(node.tokens.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

/// Whether `ast` has the top-level command `context` and, when `child` is given, the
/// command `child` anywhere beneath it.
pub(crate) fn context_has_child(ast: &Ast, context: &str, child: Option<&str>) -> bool {
    let context_words = command(context);
    let child_words = child.map(command);
    !context_words.is_empty()
        && ast
            .nodes
            .iter()
            .filter(|node| node.tokens == context_words)
            .any(|node| {
                child_words
                    .as_deref()
                    .is_none_or(|words| !words.is_empty() && beneath(node, words))
            })
}

/// Every command beneath a top-level command, in source order, with that top-level command.
pub(crate) fn nested(ast: &Ast) -> Vec<(&Node, &Node)> {
    let mut found = Vec::new();
    for context in &ast.nodes {
        let mut pending = context.children.iter().rev().collect::<Vec<_>>();
        while let Some(node) = pending.pop() {
            found.push((context, node));
            pending.extend(node.children.iter().rev());
        }
    }
    found
}

/// The word texts of `tokens`, an `ns3` blob as its payload.
pub(crate) fn texts(tokens: &[Token]) -> Vec<&str> {
    tokens
        .iter()
        .filter_map(|token| match token {
            Token::Word(word) | Token::Ns3(word) => Some(word.as_str()),
            _ => None,
        })
        .collect()
}

/// Whether `tokens` is a command anywhere beneath `node`.
fn beneath(node: &Node, tokens: &[Token]) -> bool {
    node.children
        .iter()
        .any(|child| child.tokens == tokens || beneath(child, tokens))
}
