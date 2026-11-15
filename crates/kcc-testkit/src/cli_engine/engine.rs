//! Table-driven mutations of the fake router's running CLI AST.

use kcc_config::config_text::{Ast, Node, Token, parse};

use super::{
    rules::classify,
    secrets::protect_secrets,
    tokens::{node_from_tokens, starts_with, words},
};

/// Storage shape of a recognized command.
#[derive(Clone, Copy)]
pub(super) struct Shape {
    /// Leading words stored as the context node.
    pub context_words: usize,
    /// Leaf words forming the replacement identity.
    pub identity_words: usize,
    /// Whether removal matches the complete command.
    pub exact_removal: bool,
}

/// Applies a recognized command, returning whether the line belongs to the local shape table.
pub(crate) fn apply(ast: &mut Ast, line: &str) -> bool {
    if let Some(name) = line.strip_prefix("ndns drop-name ")
        && !apply(ast, &format!("no ndns book-name {name}"))
    {
        return false;
    }
    let Ok(mut parsed) = parse(line) else {
        return false;
    };
    let Some(mut command) = parsed.nodes.pop() else {
        return false;
    };
    let command_words = words(&command.tokens);
    let (negated, positive_words) = match command_words.as_slice() {
        [first, rest @ ..] if first == "no" => (true, rest),
        words => (false, words),
    };
    if negated && starts_with(positive_words, &["ip", "hotspot", "host"]) {
        return false;
    }
    if apply_known_host(ast, positive_words, negated) {
        return true;
    }
    if super::acl_rules::apply(ast, positive_words, negated) {
        return true;
    }
    let Some(shape) = classify(positive_words) else {
        return false;
    };
    if !protect_secrets(&mut command.tokens, positive_words) {
        return false;
    }
    let mut positive_tokens = command.tokens;
    if negated {
        drop(positive_tokens.remove(0));
    }
    mutate(ast, &positive_tokens, shape, negated);
    true
}

/// Applies creation, replacement, or removal to an AST.
fn mutate(ast: &mut Ast, tokens: &[Token], shape: Shape, negated: bool) {
    if shape.context_words == 0 {
        mutate_nodes(
            &mut ast.nodes,
            tokens,
            shape.identity_words,
            shape.exact_removal,
            negated,
        );
        return;
    }
    let Some((context_tokens, leaf_tokens)) = tokens.split_at_checked(shape.context_words) else {
        return;
    };
    if leaf_tokens.is_empty() {
        match (
            negated,
            ast.nodes.iter().any(|node| node.tokens == context_tokens),
        ) {
            (true, _) => ast.nodes.retain(|node| node.tokens != context_tokens),
            (false, false) => {
                let Some(context) = node_from_tokens(context_tokens) else {
                    return;
                };
                ast.nodes.push(context);
            }
            (false, true) => {}
        }
        return;
    }
    let context = match ast
        .nodes
        .iter_mut()
        .find(|node| node.tokens == context_tokens)
    {
        Some(found) => found,
        None if negated => return,
        None => {
            let Some(node) = node_from_tokens(context_tokens) else {
                return;
            };
            ast.nodes.push_mut(node)
        }
    };
    // `up` and `down` are one interface state: the one written last replaces the other.
    let replaced = match leaf_tokens {
        [Token::Word(state)] if !negated && state == "up" => Some("down"),
        [Token::Word(state)] if !negated && state == "down" => Some("up"),
        _ => None,
    };
    if let Some(opposite) = replaced {
        context.children.retain(
            |node| !matches!(node.tokens.as_slice(), [Token::Word(word)] if word == opposite),
        );
    }
    mutate_nodes(
        &mut context.children,
        leaf_tokens,
        shape.identity_words,
        false,
        negated,
    );
}

/// Mutates one sibling list by identity prefix.
fn mutate_nodes(
    nodes: &mut Vec<Node>,
    tokens: &[Token],
    identity_words: usize,
    exact_removal: bool,
    negated: bool,
) {
    let identity = tokens.get(..identity_words).unwrap_or(tokens);
    let matches = |node: &Node| {
        if exact_removal {
            node.tokens == tokens
        } else {
            node.tokens.get(..identity.len()) == Some(identity)
        }
    };
    let position = nodes.iter().position(matches);
    nodes.retain(|node| !matches(node));
    if !negated && let Some(node) = node_from_tokens(tokens) {
        nodes.insert(position.unwrap_or(nodes.len()), node);
    }
}

/// Applies registration and its removal cascade.
fn apply_known_host(ast: &mut Ast, command: &[String], negated: bool) -> bool {
    match (negated, command) {
        (false, [known, host, _, _]) if known == "known" && host == "host" => {
            let Some(node) = parse(&command.join(" "))
                .ok()
                .and_then(|mut parsed| parsed.nodes.pop())
            else {
                return false;
            };
            let mac = command.get(3).map_or("", String::as_str);
            ast.nodes.retain(|candidate| {
                let candidate_words = words(&candidate.tokens);
                !(starts_with(&candidate_words, &["known", "host"])
                    && candidate_words.get(3).is_some_and(|value| value == mac))
            });
            ast.nodes.push(node);
            true
        }
        (true, [known, host, mac]) if known == "known" && host == "host" => {
            ast.nodes.retain(|candidate| {
                let candidate_words = words(&candidate.tokens);
                let registered = starts_with(&candidate_words, &["known", "host"])
                    && candidate_words.get(3) == Some(mac);
                let hotspot = starts_with(&candidate_words, &["ip", "hotspot", "host"])
                    && candidate_words.get(3) == Some(mac);
                !registered && !hotspot
            });
            true
        }
        (false | true, _) => false,
    }
}
