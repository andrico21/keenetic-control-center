//! Table-driven mutations of the fake router's running CLI AST.

use core::fmt::Write as _;

use kcc_config::{
    config_text::{Ast, Node, Token, parse},
    ns3,
};
use md5::{Digest as _, Md5};
use secrecy::SecretString;

/// Storage shape of a recognized command.
#[derive(Clone, Copy)]
struct Shape {
    /// Leading words stored as the context node.
    context_words: usize,
    /// Leaf words forming the replacement identity.
    identity_words: usize,
    /// Whether removal matches the complete command.
    exact_removal: bool,
}

/// Accepted leaf grammar beneath a context.
#[derive(Clone, Copy)]
struct LeafRule {
    /// Literal leaf prefix.
    prefix: &'static [&'static str],
    /// Minimum leaf length.
    minimum: usize,
    /// Optional maximum leaf length.
    maximum: Option<usize>,
    /// Words forming the replacement identity.
    identity_words: usize,
}

/// Interface context shapes.
const INTERFACE_RULES: &[LeafRule] = &[
    leaf(&["description"], 2, Some(2), 1),
    leaf(&["ip", "address"], 3, Some(4), 2),
    leaf(&["ip", "global"], 2, Some(3), 2),
    leaf(&["ip", "access-group"], 4, Some(4), 4),
    leaf(&["security-level"], 2, Some(2), 1),
    leaf(&["up"], 1, Some(1), 1),
    leaf(&["down"], 1, Some(1), 1),
    leaf(&["ssid"], 2, Some(2), 1),
    leaf(&["authentication", "wpa-psk"], 3, Some(4), 2),
    leaf(&["encryption"], 2, Some(3), 1),
    leaf(&["hide-ssid"], 1, Some(2), 1),
    leaf(&["channel"], 2, None, 1),
    leaf(&["schedule"], 2, Some(2), 1),
    leaf(&["vlan-id"], 2, Some(2), 1),
    leaf(&["include"], 2, None, 2),
    leaf(&["inherit"], 2, None, 2),
    leaf(&["switchport"], 2, None, 2),
    leaf(&["wireguard", "private-key"], 2, Some(3), 2),
    leaf(&["wireguard", "listen-port"], 3, Some(3), 2),
    leaf(&["wireguard", "peer"], 3, Some(3), 3),
    leaf(&["wireguard", "peer"], 4, None, 4),
];

/// DHCP pool context shapes.
const DHCP_POOL_RULES: &[LeafRule] = &[
    leaf(&["range"], 3, Some(3), 1),
    leaf(&["default-router"], 2, Some(2), 1),
    leaf(&["dns-server"], 2, Some(3), 2),
    leaf(&["lease"], 2, Some(2), 1),
    leaf(&["bind"], 2, Some(2), 1),
    leaf(&["enable"], 1, Some(1), 1),
];

/// User context shapes.
const USER_RULES: &[LeafRule] = &[
    leaf(&["password", "plain"], 3, Some(3), 1),
    leaf(&["password", "md5"], 3, Some(3), 1),
    leaf(&["password", "nt"], 3, Some(3), 1),
    leaf(&["tag"], 2, Some(2), 2),
];

/// Connection-policy context shapes.
const POLICY_RULES: &[LeafRule] = &[
    leaf(&["description"], 2, Some(2), 1),
    leaf(&["permit"], 2, None, 2),
    leaf(&["multipath"], 1, None, 1),
    leaf(&["route"], 2, None, 2),
    leaf(&["rate-limit"], 2, None, 1),
    leaf(&["standalone"], 1, Some(1), 1),
];

/// Access-list context shapes.
const ACCESS_LIST_RULES: &[LeafRule] = &[
    leaf(&["permit"], 2, None, 2),
    leaf(&["deny"], 2, None, 2),
    leaf(&["rule"], 2, None, 2),
    leaf(&["description"], 2, Some(2), 1),
    leaf(&["disable"], 1, Some(2), 1),
    leaf(&["schedule"], 2, Some(2), 1),
];

/// Schedule context shapes.
const SCHEDULE_RULES: &[LeafRule] = &[
    leaf(&["description"], 2, Some(2), 1),
    leaf(&["action"], 2, None, 2),
    leaf(&["weekly"], 2, None, 2),
];

/// Builds one constant leaf rule.
const fn leaf(
    prefix: &'static [&'static str],
    minimum: usize,
    maximum: Option<usize>,
    identity_words: usize,
) -> LeafRule {
    LeafRule {
        prefix,
        minimum,
        maximum,
        identity_words,
    }
}

/// Applies a recognized command, returning whether the line belongs to the local shape table.
pub(super) fn apply(ast: &mut Ast, line: &str) -> bool {
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

/// Classifies context commands through the local shape table.
fn classify(command: &[String]) -> Option<Shape> {
    let context = [
        (&["interface"][..], 2_usize, INTERFACE_RULES),
        (&["ip", "dhcp", "pool"][..], 4_usize, DHCP_POOL_RULES),
        (&["ip", "policy"][..], 3_usize, POLICY_RULES),
        (&["access-list"][..], 2_usize, ACCESS_LIST_RULES),
        (&["user"][..], 2_usize, USER_RULES),
        (&["schedule"][..], 2_usize, SCHEDULE_RULES),
    ];
    for (prefix, context_words, rules) in context {
        if starts_with(command, prefix) && command.len() >= context_words {
            if command.len() == context_words {
                return Some(Shape {
                    context_words,
                    identity_words: 0,
                    exact_removal: false,
                });
            }
            let leaf_words = command.get(context_words..)?;
            let rule = rules.iter().find(|rule| matches_rule(leaf_words, rule))?;
            return Some(Shape {
                context_words,
                identity_words: rule.identity_words,
                exact_removal: false,
            });
        }
    }
    classify_top_level(command)
}

/// Classifies top-level command families.
fn classify_top_level(command: &[String]) -> Option<Shape> {
    let identity_words = if starts_with(command, &["ip", "dhcp", "host"]) && command.len() == 5 {
        4
    } else if starts_with(command, &["ip", "hotspot", "host"]) && command.len() >= 5 {
        command.len().min(6)
    } else if starts_with(command, &["ip", "hotspot", "policy"]) && command.len() >= 4 {
        command.len().min(5)
    } else if starts_with(command, &["ip", "nat"]) && command.len() == 3 {
        3
    } else if starts_with(command, &["service"]) && command.len() == 2 {
        2
    } else if starts_with(command, &["ip", "http"])
        || starts_with(command, &["ip", "ssh"])
        || starts_with(command, &["ip", "telnet"])
    {
        command.len().saturating_sub(1)
    } else if starts_with(command, &["dns-proxy", "tls", "upstream"])
        || starts_with(command, &["dns-proxy", "https", "upstream"])
        || starts_with(command, &["ip", "host"])
        || starts_with(command, &["ip", "name-server"])
        || starts_with(command, &["object-group", "fqdn"])
        || starts_with(command, &["ndns"])
        || starts_with(command, &["system", "log"])
        || starts_with(command, &["components", "install"])
        || starts_with(command, &["components", "remove"])
        || starts_with(command, &["ipv6", "route"])
        || starts_with(command, &["ip", "static"])
        || starts_with(command, &["ip", "route"])
    {
        command.len()
    } else {
        return None;
    };
    Some(Shape {
        context_words: 0,
        identity_words,
        exact_removal: starts_with(command, &["ip", "route"])
            || starts_with(command, &["ipv6", "route"])
            || starts_with(command, &["ip", "static"]),
    })
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
    nodes.retain(|node| !matches(node));
    if !negated && let Some(node) = node_from_tokens(tokens) {
        nodes.push(node);
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

/// Replaces plaintext secret tokens before AST insertion.
fn protect_secrets(tokens: &mut [Token], command: &[String]) -> bool {
    if starts_with(command, &["interface"])
        && command
            .windows(2)
            .any(|pair| pair == ["authentication", "wpa-psk"])
        && !command.iter().any(|word| word == "ns3")
    {
        return encode_last(tokens);
    }
    if command
        .windows(2)
        .any(|pair| pair == ["wireguard", "preshared-key"])
        && !command.iter().any(|word| word == "ns3")
    {
        return encode_last(tokens);
    }
    if starts_with(command, &["user"])
        && command.get(2).is_some_and(|word| word == "password")
        && command.get(3).is_some_and(|word| word == "plain")
    {
        let Some(Token::Word(secret)) = tokens.last() else {
            return false;
        };
        let digest = Md5::digest(secret.as_bytes());
        let mut encoded = String::with_capacity(32);
        for byte in digest {
            let _result = write!(encoded, "{byte:02x}");
        }
        let length = tokens.len();
        let Some(format_token) = tokens.get_mut(length.saturating_sub(2)) else {
            return false;
        };
        *format_token = Token::Word("md5".to_owned());
        let Some(secret_token) = tokens.last_mut() else {
            return false;
        };
        *secret_token = Token::Word(encoded);
    }
    true
}

/// Encodes the final token as NS3.
fn encode_last(tokens: &mut [Token]) -> bool {
    let Some(Token::Word(plaintext)) = tokens.last() else {
        return false;
    };
    let secret = SecretString::from(plaintext.clone());
    let Ok(encoded) = ns3::encode(&secret) else {
        return false;
    };
    let Some(last) = tokens.last_mut() else {
        return false;
    };
    *last = Token::Ns3(encoded);
    true
}

/// Tests a literal command prefix.
fn starts_with(words: &[String], prefix: &[&str]) -> bool {
    words
        .iter()
        .map(String::as_str)
        .zip(prefix.iter().copied())
        .all(|(word, expected)| word == expected)
        && words.len() >= prefix.len()
}

/// Tests one leaf rule.
fn matches_rule(words: &[String], rule: &LeafRule) -> bool {
    starts_with(words, rule.prefix)
        && words.len() >= rule.minimum
        && rule.maximum.is_none_or(|maximum| words.len() <= maximum)
}

/// Expands tokens into ordinary CLI words.
fn words(tokens: &[Token]) -> Vec<String> {
    let mut result = Vec::new();
    for token in tokens {
        match token {
            Token::Word(word) => result.push(word.clone()),
            Token::Ns3(blob) => {
                result.push("ns3".to_owned());
                result.push(blob.clone());
            }
            _ => {}
        }
    }
    result
}

/// Synthesizes a node through the public parser.
fn node_from_tokens(tokens: &[Token]) -> Option<Node> {
    parse(&NodeProxy(tokens).to_text()).ok()?.nodes.pop()
}

/// Canonical text adapter for token slices.
struct NodeProxy<'tokens>(&'tokens [Token]);

impl NodeProxy<'_> {
    /// Serializes the token slice for reparsing.
    fn to_text(&self) -> String {
        let mut text = String::new();
        for (index, token) in self.0.iter().enumerate() {
            if index > 0 {
                text.push(' ');
            }
            match token {
                Token::Word(word) => write_word(&mut text, word),
                Token::Ns3(blob) => {
                    text.push_str("ns3 ");
                    write_word(&mut text, blob);
                }
                _ => {}
            }
        }
        text
    }
}

/// Writes one safely quoted ordinary word.
fn write_word(output: &mut String, word: &str) {
    if word.is_empty() || word.chars().any(char::is_whitespace) {
        output.push('"');
        output.push_str(&word.replace('\\', "\\\\").replace('"', "\\\""));
        output.push('"');
    } else {
        output.push_str(word);
    }
}
