//! CLI token conversion for simulator mutations.

use kcc_config::config_text::{Node, Token, parse};

/// Tests a literal command prefix.
pub(super) fn starts_with(words: &[String], prefix: &[&str]) -> bool {
    words
        .iter()
        .map(String::as_str)
        .zip(prefix.iter().copied())
        .all(|(word, expected)| word == expected)
        && words.len() >= prefix.len()
}

/// Expands tokens into ordinary CLI words.
pub(super) fn words(tokens: &[Token]) -> Vec<String> {
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
pub(super) fn node_from_tokens(tokens: &[Token]) -> Option<Node> {
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
