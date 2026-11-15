//! The three secret classifiers kcc had before the shared masker.
//!
//! They are copied here only to prove that the shared one masks a superset of each. The
//! markers are parameters so a comparison can tell a masked value from the original.

use kcc_config::config_text::{Ast, Node, Token};
use serde_json::Value;

/// The former MCP `redact_secrets`: substring match, the whole member replaced.
pub(crate) fn mcp(value: &mut Value, marker: &str) {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                let lowered = key.to_ascii_lowercase();
                if [
                    "password",
                    "passwd",
                    "token",
                    "secret",
                    "api_key",
                    "private_key",
                    "ns3",
                    "psk",
                    "preshared",
                ]
                .iter()
                .any(|needle| lowered.contains(needle))
                {
                    *nested = Value::String(marker.to_owned());
                } else {
                    mcp(nested, marker);
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(|nested| mcp(nested, marker)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// The former Web `is_secret`.
fn web_is_secret(name: &str) -> bool {
    const EXACT: [&str; 9] = [
        "key",
        "psk",
        "pin",
        "secret",
        "password",
        "passwd",
        "token",
        "authtoken",
        "community",
    ];
    const SUFFIXES: [&str; 5] = ["-key", "secret", "password", "passwd", "psk"];
    let lower = name.to_ascii_lowercase();
    EXACT.contains(&lower.as_str()) || SUFFIXES.iter().any(|suffix| lower.ends_with(suffix))
}

/// The former Web `mask`: scalar secret members only.
pub(crate) fn web(value: &mut Value, marker: &str) {
    match value {
        Value::Object(object) => {
            for (name, member) in object.iter_mut() {
                if web_is_secret(name) && !member.is_object() && !member.is_array() {
                    *member = Value::String(marker.to_owned());
                } else {
                    web(member, marker);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|item| web(item, marker)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// The former configuration-text pipeline: the old registry, then every `ns3` token
/// replaced by `marker`.
pub(crate) fn config(ast: &Ast, marker: &str) -> Ast {
    let mut copy = ast.clone();
    redact_nodes(&mut copy.nodes, &mut Vec::new(), marker);
    mask(&mut copy.nodes, marker);
    copy
}

/// The former consumers' `mask`.
fn mask(nodes: &mut [Node], marker: &str) {
    for node in nodes {
        for token in &mut node.tokens {
            if matches!(token, Token::Ns3(_)) {
                *token = Token::Word(marker.to_owned());
            }
        }
        mask(&mut node.children, marker);
    }
}

/// The former `secrets::redact_nodes`.
fn redact_nodes(nodes: &mut [Node], ancestors: &mut Vec<Token>, marker: &str) {
    for node in nodes {
        let previous_len = ancestors.len();
        ancestors.extend(node.tokens.iter().cloned());
        if node.children.is_empty() {
            let mut path = ancestors.clone();
            let words = expanded_words(&path);
            if let Some(index) = secret_word_index(&words) {
                replace_expanded_word(&mut path, index, marker);
            }
            let own_length = node.tokens.len();
            let path_length = path.len();
            node.tokens = path
                .into_iter()
                .skip(path_length.saturating_sub(own_length))
                .collect();
        } else {
            redact_nodes(&mut node.children, ancestors, marker);
        }
        ancestors.truncate(previous_len);
    }
}

/// The former `secrets::expanded_words`.
fn expanded_words(tokens: &[Token]) -> Vec<String> {
    tokens
        .iter()
        .flat_map(|token| match token {
            Token::Word(word) => vec![word.clone()],
            Token::Ns3(blob) => vec!["ns3".to_owned(), blob.clone()],
            _ => Vec::new(),
        })
        .collect()
}

/// The former registry.
fn secret_word_index(owned: &[String]) -> Option<usize> {
    let words: Vec<&str> = owned.iter().map(String::as_str).collect();
    let (offset, command) = match words.as_slice() {
        ["interface", _, command @ ..] => (2, command),
        all => (0, all),
    };
    match command {
        ["authentication", "wpa-psk" | "password", rest @ ..]
        | ["wireguard", "obfs-key", rest @ ..]
        | ["wireguard", "peer", _, "obfs-key", rest @ ..] => {
            secret_after_kind(argument_index(offset, command, rest), rest)
        }
        ["iapp", "key", rest @ ..] => secret_after_kind(offset.saturating_add(2), rest),
        ["ipsec", "preshared-key", rest @ ..]
        | ["crypto", "ike", "key", rest @ ..]
        | ["wireguard", "private-key", rest @ ..]
        | ["wpa-eap", "radius", "secret", rest @ ..]
        | ["snmp", "community", rest @ ..]
        | ["wireguard", "peer", _, "preshared-key", rest @ ..]
        | ["web-api", "password", rest @ ..]
        | ["ip", "http", "proxy", _, "password", rest @ ..]
        | ["user", _, "password", "md5" | "nt" | "plain", rest @ ..]
        | [
            "chilli",
            "radiussecret" | "uamsecret" | "macpasswd",
            rest @ ..,
        ] => Some(argument_index(offset, command, rest)),
        _ => None,
    }
}

/// The former `argument_index`.
const fn argument_index(offset: usize, command: &[&str], rest: &[&str]) -> usize {
    offset.saturating_add(command.len().saturating_sub(rest.len()))
}

/// The former `secret_after_kind`.
fn secret_after_kind(prefix_length: usize, rest: &[&str]) -> Option<usize> {
    match rest {
        ["ns3", _secret, ..] => Some(prefix_length.saturating_add(1)),
        [_secret, ..] => Some(prefix_length),
        [] => None,
    }
}

/// The former `replace_expanded_word`.
fn replace_expanded_word(tokens: &mut [Token], target: usize, marker: &str) {
    let mut expanded_index = 0;
    for token in tokens {
        match token {
            Token::Word(word) => {
                if expanded_index == target {
                    marker.clone_into(word);
                    return;
                }
                expanded_index = expanded_index.saturating_add(1);
            }
            Token::Ns3(blob) => {
                if expanded_index.saturating_add(1) == target {
                    marker.clone_into(blob);
                    return;
                }
                expanded_index = expanded_index.saturating_add(2);
            }
            _ => {}
        }
    }
}
