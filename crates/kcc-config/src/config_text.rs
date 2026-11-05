//! Parser and canonical formatter for Keenetic startup and running configurations.

use alloc::collections::BTreeMap;
use core::{fmt, iter::Peekable};

use thiserror::Error;

/// Metadata emitted at the beginning of a Keenetic configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct ConfigHeader {
    /// Router model.
    pub model: Option<String>,
    /// Firmware version.
    pub version: Option<String>,
    /// Agent that last generated the configuration.
    pub agent: Option<String>,
    /// Router-provided last-change timestamp.
    pub last_change: Option<String>,
    /// Router-provided MD5 checksum.
    pub md5: Option<String>,
    /// User that last changed the configuration.
    pub username: Option<String>,
    /// Unknown header fields, keyed by their original names.
    pub extra: BTreeMap<String, String>,
}

/// A lexical configuration token.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Token {
    /// An ordinary argument or command word.
    Word(String),
    /// An `ns3` marker and its encoded payload.
    Ns3(String),
}

/// One command in the indentation-derived configuration tree.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Node {
    /// Tokens on this command line.
    pub tokens: Vec<Token>,
    /// Commands nested beneath this context command.
    pub children: Vec<Self>,
    /// One-based source line number, or zero for a synthesized node.
    pub line_no: usize,
}

impl PartialEq for Node {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        let Self {
            tokens,
            children,
            line_no: _,
        } = self;
        let Self {
            tokens: other_tokens,
            children: other_children,
            line_no: _,
        } = other;
        tokens == other_tokens && children == other_children
    }
}

impl Eq for Node {}

/// A complete parsed configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Ast {
    /// Parsed configuration header.
    pub header: ConfigHeader,
    /// Top-level commands in source order.
    pub nodes: Vec<Node>,
}

/// A flattened command ready for the Keenetic CLI parser.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CliLine {
    /// Full command path, including every ancestor context.
    pub tokens: Vec<Token>,
    /// Source line number of the leaf command.
    pub line_no: usize,
}

impl fmt::Display for CliLine {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_tokens(f, &self.tokens)
    }
}

/// A malformed configuration-text error.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// A quoted token was not terminated on its source line.
    #[error("unterminated quoted token at line {line}")]
    UnterminatedQuote {
        /// One-based source line number.
        line: usize,
    },
    /// Indentation is not a multiple of the detected per-level width.
    #[error("invalid indentation at line {line}: {spaces} spaces for width {width}")]
    InvalidIndent {
        /// One-based source line number.
        line: usize,
        /// Number of leading spaces found.
        spaces: usize,
        /// Detected indentation width.
        width: usize,
    },
    /// A command skipped an indentation level.
    #[error("indentation jumps to level {level} at line {line}")]
    IndentJump {
        /// One-based source line number.
        line: usize,
        /// Invalid indentation level.
        level: usize,
    },
}

/// Parses Keenetic startup- or running-configuration text.
///
/// # Errors
///
/// Returns [`ParseError`] for malformed quoting or indentation.
#[inline]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "indentation width is nonzero and exact divisibility is validated before division"
)]
pub fn parse(input: &str) -> Result<Ast, ParseError> {
    let mut header = ConfigHeader::default();
    let mut commands = Vec::new();
    let mut indent_width = None;

    for (line_index, raw_line) in input.lines().enumerate() {
        let line_no = line_index.saturating_add(1);
        let line = raw_line.trim_end_matches('\r');
        let trimmed = line.trim_start_matches(' ');
        if let Some(header_text) = trimmed.strip_prefix("! $$$ ") {
            parse_header(&mut header, header_text);
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('!') {
            continue;
        }

        let spaces = line.len().saturating_sub(trimmed.len());
        if spaces > 0 {
            indent_width = Some(indent_width.map_or(spaces, |width: usize| width.min(spaces)));
        }
        commands.push(RawCommand {
            spaces,
            line_no,
            tokens: tokenize(trimmed, line_no)?,
        });
    }

    let width = indent_width.unwrap_or(1);
    let mut leveled = Vec::with_capacity(commands.len());
    for command in commands {
        if command.spaces % width != 0 {
            return Err(ParseError::InvalidIndent {
                line: command.line_no,
                spaces: command.spaces,
                width,
            });
        }
        leveled.push(LeveledNode {
            level: command.spaces / width,
            node: Node {
                tokens: command.tokens,
                children: Vec::new(),
                line_no: command.line_no,
            },
        });
    }

    let mut input_nodes = leveled.into_iter().peekable();
    let nodes = parse_level(&mut input_nodes, 0)?;
    Ok(Ast { header, nodes })
}

/// Prints an AST in canonical Keenetic form.
#[must_use]
#[inline]
pub fn print(ast: &Ast) -> String {
    let mut output = String::new();
    write_header(&mut output, &ast.header);
    for node in &ast.nodes {
        write_node(&mut output, node, 0);
        output.push_str("!\n");
    }
    output
}

/// Parses and reprints text using canonical whitespace and quoting.
///
/// # Errors
///
/// Returns [`ParseError`] when the input cannot be parsed.
#[inline]
pub fn normalize(input: &str) -> Result<String, ParseError> {
    parse(input).map(|ast| print(&ast))
}

/// Flattens every leaf into a full ancestor-prefixed CLI command.
#[must_use]
#[inline]
pub fn flatten(ast: &Ast) -> Vec<CliLine> {
    let mut lines = Vec::new();
    let mut ancestors = Vec::new();
    flatten_nodes(&ast.nodes, &mut ancestors, &mut lines);
    lines
}

/// Unparsed command with physical indentation.
struct RawCommand {
    /// Leading spaces.
    spaces: usize,
    /// Source line.
    line_no: usize,
    /// Parsed tokens.
    tokens: Vec<Token>,
}

/// Node paired with its logical indentation level.
struct LeveledNode {
    /// Zero-based indentation level.
    level: usize,
    /// Parsed node.
    node: Node,
}

/// Parses a forest at one indentation level.
///
/// # Errors
///
/// Returns [`ParseError::IndentJump`] when a command skips a tree level.
fn parse_level<I>(input: &mut Peekable<I>, expected_level: usize) -> Result<Vec<Node>, ParseError>
where
    I: Iterator<Item = LeveledNode>,
{
    let mut nodes = Vec::new();
    while let Some(next) = input.peek() {
        if next.level < expected_level {
            break;
        }
        if next.level > expected_level {
            return Err(ParseError::IndentJump {
                line: next.node.line_no,
                level: next.level,
            });
        }
        let Some(mut item) = input.next() else {
            break;
        };
        item.node.children = parse_level(input, expected_level.saturating_add(1))?;
        nodes.push(item.node);
    }
    Ok(nodes)
}

/// Parses one metadata header field.
fn parse_header(header: &mut ConfigHeader, text: &str) {
    let Some((key, raw_value)) = text.split_once(':') else {
        return;
    };
    let value = raw_value.trim().to_owned();
    match key.trim().to_ascii_lowercase().as_str() {
        "model" => header.model = Some(value),
        "version" => header.version = Some(value),
        "agent" => header.agent = Some(value),
        "last change" => header.last_change = Some(value),
        "md5" | "md5 checksum" => header.md5 = Some(value),
        "username" => header.username = Some(value),
        _ => {
            drop(header.extra.insert(key.trim().to_owned(), value));
        }
    }
}

/// Tokenizes a single command and folds `ns3 <blob>` into one typed token.
///
/// # Errors
///
/// Returns [`ParseError::UnterminatedQuote`] for an unclosed quoted argument.
fn tokenize(line: &str, line_no: usize) -> Result<Vec<Token>, ParseError> {
    let mut words = Vec::new();
    let mut chars = line.chars().peekable();
    while chars.peek().is_some() {
        while chars
            .next_if(|character| character.is_whitespace())
            .is_some()
        {}
        if chars.peek().is_none() {
            break;
        }
        let mut word = String::new();
        if chars.next_if_eq(&'"').is_some() {
            let mut closed = false;
            while let Some(character) = chars.next() {
                match character {
                    '"' => {
                        closed = true;
                        break;
                    }
                    '\\' => match chars.next() {
                        Some('"') => word.push('"'),
                        Some('\\') | None => word.push('\\'),
                        Some(other) => {
                            word.push('\\');
                            word.push(other);
                        }
                    },
                    other => word.push(other),
                }
            }
            if !closed {
                return Err(ParseError::UnterminatedQuote { line: line_no });
            }
        } else {
            while let Some(character) = chars.next_if(|character| !character.is_whitespace()) {
                word.push(character);
            }
        }
        words.push(word);
    }

    let mut tokens = Vec::with_capacity(words.len());
    let mut word_iter = words.into_iter();
    while let Some(word) = word_iter.next() {
        if word == "ns3"
            && let Some(blob) = word_iter.next()
        {
            tokens.push(Token::Ns3(blob));
        } else {
            tokens.push(Token::Word(word));
        }
    }
    Ok(tokens)
}

/// Writes known headers in stable order, followed by unknown fields.
fn write_header(output: &mut String, header: &ConfigHeader) {
    write_header_field(output, "Model", header.model.as_deref());
    write_header_field(output, "Version", header.version.as_deref());
    write_header_field(output, "Agent", header.agent.as_deref());
    write_header_field(output, "Last change", header.last_change.as_deref());
    write_header_field(output, "Md5 checksum", header.md5.as_deref());
    write_header_field(output, "Username", header.username.as_deref());
    for (key, value) in &header.extra {
        output.push_str("! $$$ ");
        output.push_str(key);
        output.push_str(": ");
        output.push_str(value);
        output.push('\n');
    }
}

/// Writes an optional header field.
fn write_header_field(output: &mut String, key: &str, field_value: Option<&str>) {
    if let Some(value) = field_value {
        output.push_str("! $$$ ");
        output.push_str(key);
        output.push_str(": ");
        output.push_str(value);
        output.push('\n');
    }
}

/// Writes one node and all descendants.
fn write_node(output: &mut String, node: &Node, depth: usize) {
    for _ in 0..depth {
        output.push(' ');
    }
    let Ok(()) = write_tokens(output, &node.tokens) else {
        return;
    };
    output.push('\n');
    for child in &node.children {
        write_node(output, child, depth.saturating_add(1));
    }
}

/// Writes tokens in their canonical CLI representation.
///
/// # Errors
///
/// Returns the destination writer's formatting error.
fn write_tokens<W>(output: &mut W, tokens: &[Token]) -> fmt::Result
where
    W: fmt::Write + ?Sized,
{
    for (position, token) in tokens.iter().enumerate() {
        if position > 0 {
            output.write_char(' ')?;
        }
        match token {
            Token::Word(word) => write_word(output, word)?,
            Token::Ns3(blob) => {
                output.write_str("ns3 ")?;
                write_word(output, blob)?;
            }
        }
    }
    Ok(())
}

/// Writes a word, quoting and escaping it only when required.
///
/// # Errors
///
/// Returns the destination writer's formatting error.
fn write_word<W>(output: &mut W, word: &str) -> fmt::Result
where
    W: fmt::Write + ?Sized,
{
    if word.is_empty()
        || word
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '"' | '\\'))
    {
        output.write_char('"')?;
        for character in word.chars() {
            if matches!(character, '"' | '\\') {
                output.write_char('\\')?;
            }
            output.write_char(character)?;
        }
        output.write_char('"')
    } else {
        output.write_str(word)
    }
}

/// Recursively emits leaf paths while preserving source order.
fn flatten_nodes(nodes: &[Node], ancestors: &mut Vec<Token>, output: &mut Vec<CliLine>) {
    for node in nodes {
        let previous_len = ancestors.len();
        ancestors.extend(node.tokens.iter().cloned());
        if node.children.is_empty() {
            output.push(CliLine {
                tokens: ancestors.clone(),
                line_no: node.line_no,
            });
        } else {
            flatten_nodes(&node.children, ancestors, output);
        }
        ancestors.truncate(previous_len);
    }
}

#[cfg(test)]
mod tests {
    //! Property checks for parser safety and AST stability.

    use alloc::collections::BTreeMap;

    use proptest::{
        prelude::{any, prop, prop_compose, proptest},
        strategy::Strategy,
    };

    use super::{Ast, ConfigHeader, Node, Token, flatten, normalize, parse, print};

    prop_compose! {
        /// Generates token text that needs no canonical escaping ambiguity.
        fn word()(value in "[A-Za-z0-9_./:+-]{1,16}") -> String {
            value
        }
    }

    prop_compose! {
        /// Generates one ordinary or typed NS3 token.
        fn token()(is_ns3 in any::<bool>(), value in word()) -> Token {
            if is_ns3 { Token::Ns3(value) } else { Token::Word(value) }
        }
    }

    /// Generates a bounded node tree without recursion-heavy shrinking.
    fn node() -> impl Strategy<Value = Node> {
        prop::collection::vec(token(), 1..5)
            .prop_map(|tokens| Node {
                tokens,
                children: Vec::new(),
                line_no: 0,
            })
            .prop_recursive(3, 32, 4, |child_strategy| {
                (
                    prop::collection::vec(token(), 1..5),
                    prop::collection::vec(child_strategy, 0..4),
                )
                    .prop_map(|(tokens, children)| Node {
                        tokens,
                        children,
                        line_no: 0,
                    })
            })
    }

    /// Generates complete ASTs for canonical round-trip testing.
    fn ast() -> impl Strategy<Value = Ast> {
        prop::collection::vec(node(), 0..6).prop_map(|nodes| Ast {
            header: ConfigHeader {
                model: Some("KN-1811".to_owned()),
                version: Some("4.2".to_owned()),
                agent: None,
                last_change: None,
                md5: None,
                username: None,
                extra: BTreeMap::new(),
            },
            nodes,
        })
    }

    proptest! {
        /// Arbitrary UTF-8 input is always handled without a panic.
        #[test]
        fn arbitrary_input_never_panics(input in ".*") {
            let _result = parse(&input);
        }

        /// Canonical serialization preserves generated AST structure.
        #[test]
        fn printed_ast_round_trips(generated in ast()) {
            let text = print(&generated);
            let parsed = parse(&text)?;
            proptest::prop_assert_eq!(parsed, generated);
        }
    }

    /// Checks four-space indentation and escaped quoted arguments.
    ///
    /// # Panics
    ///
    /// Panics when valid export text does not parse, normalize, or flatten canonically.
    #[test]
    fn parses_export_indentation_and_escaped_quotes() {
        let text = "interface Bridge0\n    description \"Home \\\"LAN\\\" \\\\ core\"\n!\n";
        let ast = parse(text);
        assert!(ast.is_ok(), "valid export must parse");
        let canonical = "interface Bridge0\n description \"Home \\\"LAN\\\" \\\\ core\"\n!\n";
        assert_eq!(ast.as_ref().map(print).as_deref(), Ok(canonical));
        assert_eq!(normalize(text).as_deref(), Ok(canonical));
        assert_eq!(
            ast.as_ref()
                .ok()
                .and_then(|parsed| flatten(parsed).first().map(ToString::to_string)),
            Some("interface Bridge0 description \"Home \\\"LAN\\\" \\\\ core\"".to_owned())
        );
    }
}
