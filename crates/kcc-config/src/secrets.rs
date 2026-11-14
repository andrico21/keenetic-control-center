//! Secret-path registry and structural redaction.

use crate::config_text::{Ast, Node, Token};

/// Literal used in place of every registered secret.
const REDACTED: &str = "<redacted>";

/// Returns a deep copy with every registered command secret replaced.
#[must_use]
#[inline]
pub fn redact(ast: &Ast) -> Ast {
    let mut redacted = ast.clone();
    redact_nodes(&mut redacted.nodes, &mut Vec::new());
    redacted
}

/// Traverses the tree while retaining each command's full path.
fn redact_nodes(nodes: &mut [Node], ancestors: &mut Vec<Token>) {
    for node in nodes {
        let previous_len = ancestors.len();
        ancestors.extend(node.tokens.iter().cloned());
        if node.children.is_empty() {
            let mut path = ancestors.clone();
            redact_path(&mut path);
            let own_length = node.tokens.len();
            let path_length = path.len();
            node.tokens = path
                .into_iter()
                .skip(path_length.saturating_sub(own_length))
                .collect();
        } else {
            redact_nodes(&mut node.children, ancestors);
        }
        ancestors.truncate(previous_len);
    }
}

/// Applies the registry to one flattened token path.
fn redact_path(tokens: &mut [Token]) {
    let words = expanded_words(tokens);
    if let Some(secret_index) = secret_word_index(&words) {
        replace_expanded_word(tokens, secret_index);
    }
}

/// The CLI words of `tokens`, for matching a command path: an ordinary word as itself, a
/// typed `ns3` token as the two words `ns3` and its payload.
#[must_use]
#[inline]
pub fn expanded_words(tokens: &[Token]) -> Vec<&str> {
    let mut words = Vec::new();
    for token in tokens {
        match token {
            Token::Word(word) => words.push(word.as_str()),
            Token::Ns3(blob) => {
                words.push("ns3");
                words.push(blob.as_str());
            }
        }
    }
    words
}

/// Finds the secret argument's index in the expanded command path.
fn secret_word_index(words: &[&str]) -> Option<usize> {
    let (offset, command) = match words {
        ["interface", _, command @ ..] => (2, command),
        _ => (0, words),
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

/// Computes the first argument index after a matched command prefix.
const fn argument_index(offset: usize, command: &[&str], rest: &[&str]) -> usize {
    offset.saturating_add(command.len().saturating_sub(rest.len()))
}

/// Accounts for an optional `ns3` kind marker before a password payload.
fn secret_after_kind(prefix_length: usize, rest: &[&str]) -> Option<usize> {
    match rest {
        ["ns3", _secret, ..] => Some(prefix_length.saturating_add(1)),
        [_secret, ..] => Some(prefix_length),
        [] => None,
    }
}

/// Replaces an expanded word while preserving typed NS3 structure.
fn replace_expanded_word(tokens: &mut [Token], target: usize) {
    let mut expanded_index = 0;
    for token in tokens {
        match token {
            Token::Word(word) => {
                if expanded_index == target {
                    REDACTED.clone_into(word);
                    return;
                }
                expanded_index = expanded_index.saturating_add(1);
            }
            Token::Ns3(blob) => {
                if expanded_index.saturating_add(1) == target {
                    REDACTED.clone_into(blob);
                    return;
                }
                expanded_index = expanded_index.saturating_add(2);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Coverage for every registered secret-bearing command path.

    use super::{REDACTED, redact};
    use crate::config_text::{flatten, parse};

    /// Confirms every registry entry is redacted without changing benign arguments.
    ///
    /// # Panics
    ///
    /// Panics when a registry path leaks its fixture secret or benign content changes.
    #[test]
    fn redacts_complete_registry() {
        let input = concat!(
            "interface WifiMaster0/AccessPoint0\n authentication wpa-psk ns3 alpha\n!\n",
            "interface PPPoE0\n authentication password ns3 beta\n!\n",
            "interface Bridge0\n iapp key ns3 gamma\n web-api password delta\n!\n",
            "ipsec preshared-key epsilon\n",
            "wireguard private-key zeta\n",
            "wireguard peer peer0 preshared-key eta\n",
            "interface Wireguard0\n wireguard obfs-key obfuscated-interface\n wireguard peer peer0 obfs-key obfuscated-peer\n!\n",
            "crypto ike key theta\n",
            "user admin password md5 iota\n",
            "user admin password nt kappa\n",
            "user admin password plain lambda\n",
            "chilli radiussecret mu\n",
            "chilli uamsecret nu\n",
            "chilli macpasswd xi\n",
            "wpa-eap radius secret omicron\n",
            "snmp community pi\n",
            "ip http proxy upstream password rho\n",
            "system description visible\n",
        );
        let parsed = parse(input);
        assert!(parsed.is_ok(), "registry fixture must parse");
        let lines: Vec<String> = parsed
            .as_ref()
            .map(redact)
            .map_or_default(|ast| flatten(&ast))
            .into_iter()
            .map(|line| line.to_string())
            .collect();
        assert_eq!(lines.len(), 20, "all commands remain present");
        assert_eq!(
            lines.iter().filter(|line| line.contains(REDACTED)).count(),
            19,
            "every registered secret is replaced: {lines:?}"
        );
        assert_eq!(
            lines.last().map(String::as_str),
            Some("system description visible")
        );
        for secret in [
            "alpha",
            "beta",
            "gamma",
            "delta",
            "epsilon",
            "zeta",
            "eta",
            "theta",
            "iota",
            "kappa",
            "lambda",
            "mu",
            "nu",
            "xi",
            "omicron",
            "pi",
            "rho",
            "obfuscated-interface",
            "obfuscated-peer",
        ] {
            assert!(
                lines
                    .iter()
                    .all(|line| !line.split_whitespace().any(|word| word == secret)),
                "secret {secret} must be absent"
            );
        }
    }
}
