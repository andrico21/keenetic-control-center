//! `catalog build`: parse extracted manuals into the committed structural command catalog.

use alloc::collections::{BTreeMap, BTreeSet};
use core::{fmt::Write as _, mem::take};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    Verdict,
    catalog::{self, Entry, Lock},
    failure::GateError,
};

/// Generator schema/version recorded in every index.
const GENERATOR_VERSION: u32 = 1;
/// Maximum committed JSON file size.
const MAX_FILE_BYTES: u64 = 900_000;
/// Minimum accepted synopsis coverage, represented as an integer percentage.
const MIN_COVERAGE_PERCENT: usize = 98;

/// A synopsis argument intentionally left without a generated type.
#[derive(Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct UntypedArgument {
    /// Full command path.
    path: String,
    /// Synopsis argument name.
    name: String,
}

/// One bookmark emitted by `catalog extract`.
#[derive(Debug, Deserialize)]
struct Bookmark {
    /// Bookmark nesting depth.
    level: usize,
    /// Bookmark title including its section number.
    title: String,
    /// One-based PDF page.
    page: usize,
}

/// A serializable command catalog file.
#[derive(Debug, Serialize)]
struct GroupFile<'catalog> {
    /// Firmware catalog version.
    version: &'catalog str,
    /// Top-level command group.
    group: &'catalog str,
    /// Commands in lexical path order.
    commands: Vec<&'catalog Command>,
}

/// A structural command record. No description or example prose is retained.
#[derive(Debug, Clone, Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "these independent manual Yes/No fields are serialized as booleans by contract"
)]
struct Command {
    /// Full command path.
    path: String,
    /// Models whose manuals document this command.
    models: BTreeSet<String>,
    /// First KeeneticOS version reported by the History table.
    since: String,
    /// PDF page from the bookmark.
    page: usize,
    /// Official PDF URL.
    source_url: String,
    /// Runtime request kind inferred from structural fields.
    kind: CommandKind,
    /// Whether `no` is accepted.
    prefix_no: bool,
    /// Whether repeated input is accepted.
    multiple_input: bool,
    /// Whether the command changes settings.
    change_settings: bool,
    /// Whether the manual states that persistence is immediate.
    persists_immediately: bool,
    /// Whether this bookmark is a command group entry.
    group_entry: bool,
    /// Interface class restriction, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    interface_type: Option<String>,
    /// CLI context entered by this command, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
    /// Parsed synopsis grammar.
    #[serde(skip_serializing_if = "Option::is_none")]
    synopsis: Option<Grammar>,
    /// Argument types keyed by argument name.
    arguments: BTreeMap<String, ValueType>,
    /// Non-fatal parser diagnostics.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    parse_warnings: Vec<String>,
}

/// Runtime request kind.
#[derive(Debug, Clone, Copy, Serialize)]
enum CommandKind {
    /// Read-only `show` command.
    Show,
    /// Configuration setting.
    Setting,
    /// Imperative action.
    Action,
}

/// Closed argument value type set from the manual.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "values")]
enum ValueType {
    /// Arbitrary text.
    String,
    /// Integer.
    Integer,
    /// IP address.
    IpAddress,
    /// IP mask.
    IpMask,
    /// IP address with mask.
    IpAddressMask,
    /// MAC address.
    MacAddress,
    /// Interface name.
    Interface,
    /// Named configuration object.
    ObjectName,
    /// Filename.
    Filename,
    /// Secret password.
    Password,
    /// Boolean.
    Boolean,
    /// Literal alternatives.
    Keyword(BTreeSet<String>),
}

/// Small synopsis grammar AST.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "node", content = "value")]
enum Grammar {
    /// Ordered nodes.
    Sequence(Vec<Self>),
    /// Optional node (`[...]`).
    Optional(Box<Self>),
    /// Parenthesized group.
    Group(Box<Self>),
    /// Alternatives separated by `|`.
    Alternative(Vec<Self>),
    /// Named argument marker.
    Argument(String),
    /// Literal command keyword.
    Keyword(String),
}

/// Per-version index metadata.
#[derive(Debug, Serialize)]
struct Index {
    /// Firmware catalog version.
    version: String,
    /// Generator schema version.
    generator_version: u32,
    /// Command group paths in manual order.
    groups: Vec<String>,
    /// Top-level JSON file groups.
    file_groups: Vec<String>,
    /// Number of union commands.
    command_count: usize,
    /// Number of leaf bookmarks in the KN-1811 reference manual.
    reference_leaf_count: usize,
    /// Leaf bookmarks with a parsed synopsis.
    synopsis_count: usize,
    /// Integer coverage percentage.
    synopsis_coverage_percent: usize,
    /// Input PDF hashes keyed by model id.
    source_sha256s: BTreeMap<String, String>,
}

/// Parsed model result before unioning.
#[derive(Debug)]
struct ModelCatalog {
    /// Commands in this model.
    commands: Vec<Command>,
    /// Chapter 3 leaf bookmark count.
    leaf_count: usize,
    /// Leaf commands with parsed synopses.
    synopsis_count: usize,
}

/// Builds one firmware-version catalog from every extracted model manual.
///
/// # Errors
///
/// Returns a [`GateError`] for missing inputs, malformed extraction data, failed gates,
/// or output errors.
pub(crate) fn run<W>(root: &Path, version: &str, out: &mut W) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    if !matches!(version, "4.3" | "5.0" | "5.1") {
        return Err(command_error(
            "catalog build",
            format!("unsupported version {version}; expected 4.3, 5.0, or 5.1"),
        ));
    }
    let lock = Lock::load(&catalog::lock_path(root))?;
    let entries: Vec<&Entry> = lock
        .entries
        .iter()
        .filter(|entry| entry.version == version && !entry.absent)
        .collect();
    if entries.is_empty() {
        return Err(command_error(
            "catalog build",
            format!("no fetched manuals for version {version}"),
        ));
    }

    let mut union = BTreeMap::<String, Command>::new();
    let mut reference_leaf_count = 0;
    let mut reference_synopsis_count = 0;
    let mut hashes = BTreeMap::new();
    let allowlist = load_untyped_allowlist(root)?;
    for entry in entries {
        let parsed = parse_model(root, entry, &allowlist)?;
        if entry.model == "KN-1811" {
            reference_leaf_count = parsed.leaf_count;
            reference_synopsis_count = parsed.synopsis_count;
        }
        if let Some(hash) = &entry.sha256 {
            drop(hashes.insert(entry.model.clone(), hash.clone()));
        }
        for command in parsed.commands {
            merge_command(&mut union, command);
        }
    }
    if reference_leaf_count == 0 {
        return Err(command_error(
            "catalog build",
            format!("KN-1811 reference manual is missing for version {version}"),
        ));
    }
    let coverage = reference_synopsis_count
        .checked_mul(100)
        .and_then(|value| value.checked_div(reference_leaf_count))
        .ok_or_else(|| command_error("catalog build", "coverage arithmetic failed".to_owned()))?;
    if coverage < MIN_COVERAGE_PERCENT {
        return Err(command_error(
            "catalog build",
            format!(
                "KN-1811 synopsis coverage {reference_synopsis_count}/{reference_leaf_count} ({coverage}%) is below {MIN_COVERAGE_PERCENT}%"
            ),
        ));
    }

    let file_groups = write_catalog(
        root,
        version,
        &union,
        &hashes,
        reference_leaf_count,
        reference_synopsis_count,
        coverage,
    )?;
    write_generated(root)?;
    writeln!(
        out,
        "catalog {version}: {} commands, {} groups, KN-1811 synopsis {reference_synopsis_count}/{reference_leaf_count} ({coverage}%)",
        union.len(),
        file_groups.len()
    )?;
    let warning_count = union
        .values()
        .filter(|command| !command.parse_warnings.is_empty())
        .count();
    writeln!(
        out,
        "catalog {version}: {warning_count} commands with parse warnings"
    )?;
    Ok(Verdict::Pass)
}

/// Parses one model's text using its bookmark list as the authoritative command list.
///
/// # Errors
///
/// Returns an input or JSON parse error when the extracted model files are unavailable or malformed.
fn parse_model(
    root: &Path,
    entry: &Entry,
    untyped_allowlist: &BTreeSet<UntypedArgument>,
) -> Result<ModelCatalog, GateError> {
    let stem = entry.model.to_lowercase();
    let base = catalog::cache_dir(root).join(&entry.version);
    let text_path = base.join(format!("{stem}.txt"));
    let outline_path = base.join(format!("{stem}.outline.json"));
    let text = read_text(&text_path)?;
    let outline_text = read_text(&outline_path)?;
    let bookmarks: Vec<Bookmark> = serde_json::from_str(&outline_text).map_err(|source| {
        command_error(
            "catalog build",
            format!("cannot parse {}: {source}", outline_path.display()),
        )
    })?;
    parse_bookmarks(&text, &bookmarks, entry, untyped_allowlist)
}

/// Loads the exact legacy exceptions to synopsis argument typing.
///
/// # Errors
///
/// Returns an input or JSON parse error when the committed allowlist is unavailable or malformed.
fn load_untyped_allowlist(root: &Path) -> Result<BTreeSet<UntypedArgument>, GateError> {
    let path = root.join("catalog/untyped-arguments.json");
    let text = read_text(&path)?;
    serde_json::from_str(&text).map_err(|source| {
        command_error(
            "catalog build",
            format!("cannot parse {}: {source}", path.display()),
        )
    })
}

/// Reads UTF-8 input with a path-aware error.
///
/// # Errors
///
/// Returns [`GateError::Read`] when `path` cannot be read as UTF-8 text.
fn read_text(path: &Path) -> Result<String, GateError> {
    fs::read_to_string(path).map_err(|source| GateError::Read {
        path: path.to_path_buf(),
        source,
    })
}

/// Parses all Chapter 3 and Appendix C command bookmarks from one manual.
///
/// # Errors
///
/// Returns a command error when a bookmarked command heading cannot be located.
fn parse_bookmarks(
    text: &str,
    bookmarks: &[Bookmark],
    entry: &Entry,
    untyped_allowlist: &BTreeSet<UntypedArgument>,
) -> Result<ModelCatalog, GateError> {
    let lines: Vec<&str> = text.lines().collect();
    let command_bookmarks: Vec<&Bookmark> = bookmarks
        .iter()
        .filter(|bookmark| command_path(&bookmark.title).is_some())
        .collect();
    let mut located = Vec::with_capacity(command_bookmarks.len());
    let mut cursor = 0;
    for bookmark in &command_bookmarks {
        let index = locate_heading(&lines, &bookmark.title, cursor).ok_or_else(|| {
            command_error(
                "catalog build",
                format!(
                    "{}: cannot locate bookmark heading {:?}",
                    entry.model, bookmark.title
                ),
            )
        })?;
        located.push(index);
        cursor = index.saturating_add(1);
    }

    let mut commands = Vec::with_capacity(located.len());
    let mut leaf_count = 0_usize;
    let mut synopsis_count = 0_usize;
    for (position, bookmark) in command_bookmarks.iter().enumerate() {
        let start = located.get(position).copied().ok_or_else(|| {
            command_error("catalog build", "located bookmark count changed".to_owned())
        })?;
        let end = located
            .get(position.saturating_add(1))
            .copied()
            .unwrap_or(lines.len());
        let path = command_path(&bookmark.title).ok_or_else(|| {
            command_error(
                "catalog build",
                format!("invalid command bookmark {}", bookmark.title),
            )
        })?;
        let section = lines.get(start..end).ok_or_else(|| {
            command_error("catalog build", format!("invalid section range for {path}"))
        })?;
        let is_leaf =
            bookmark.level >= 3 || bookmark.title.starts_with("C.") && has_synopsis(section);
        let is_group = bookmark.level == 2 || bookmark.title == "C.1 nvox";
        let command = parse_section(
            path,
            bookmark.page,
            section,
            entry,
            is_leaf,
            is_group,
            untyped_allowlist,
        );
        if is_leaf {
            leaf_count = leaf_count.saturating_add(1);
            if command.synopsis.is_some() {
                synopsis_count = synopsis_count.saturating_add(1);
            }
        }
        commands.push(command);
    }
    Ok(ModelCatalog {
        commands,
        leaf_count,
        synopsis_count,
    })
}

/// Finds an exact heading after `cursor`, rejecting table-of-contents dot leaders and
/// requiring a Description field within the next three non-empty lines.
fn locate_heading(lines: &[&str], title: &str, cursor: usize) -> Option<usize> {
    lines
        .iter()
        .enumerate()
        .skip(cursor)
        .find_map(|(index, line)| {
            let trimmed = line.trim();
            if trimmed != title || trimmed.contains("....") {
                return None;
            }
            lines
                .iter()
                .skip(index.saturating_add(1))
                .filter(|candidate| !candidate.trim().is_empty())
                .take(3)
                .any(|candidate| candidate.trim_start().starts_with("Description"))
                .then_some(index)
        })
}

/// Removes a Chapter 3 or Appendix C section number from a bookmark title.
fn command_path(title: &str) -> Option<String> {
    let (number, raw_path) = title.split_once(' ')?;
    let chapter_three = number.starts_with("3.")
        && number.split('.').all(|piece| {
            !piece.is_empty() && piece.chars().all(|character| character.is_ascii_digit())
        });
    let appendix_c = number.starts_with("C.")
        && number.split('.').skip(1).all(|piece| {
            !piece.is_empty() && piece.chars().all(|character| character.is_ascii_digit())
        });
    let command = raw_path.trim();
    (chapter_three || appendix_c && (command == "nvox" || command.starts_with("nvox ")))
        .then(|| command.to_owned())
        .filter(|candidate| !candidate.is_empty())
}

/// Parses one command section and retains only structural fields.
fn parse_section(
    path: String,
    page: usize,
    lines: &[&str],
    entry: &Entry,
    is_leaf: bool,
    is_group: bool,
    untyped_allowlist: &BTreeSet<UntypedArgument>,
) -> Command {
    let prefix_no = field_value(lines, "Prefix no").is_some_and(|value| value == "Yes");
    let change_settings = field_value(lines, "Change settings").is_some_and(|value| value == "Yes");
    let multiple_input = field_value(lines, "Multiple input").is_some_and(|value| value == "Yes");
    let interface_type = field_value(lines, "Interface type").map(str::to_owned);
    let context = field_value(lines, "Group entry").map(str::to_owned);
    let description = field_block(
        lines,
        "Description",
        &[
            "Prefix no",
            "Change settings",
            "Multiple input",
            "Interface type",
            "Group entry",
            "Synopsis",
        ],
    );
    let description_lower = description.to_ascii_lowercase();
    let persists_immediately = description_lower.contains("does not require configuration save")
        || description_lower.contains("permanently stored");
    let synopsis_text = synopsis_block(lines);
    let synopsis = synopsis_text.as_deref().and_then(parse_synopsis);
    let argument_names = synopsis_text.as_deref().map_or_default(argument_names);
    let mut arguments = parse_arguments(lines, &argument_names);
    if path.ends_with("security-level") && arguments.is_empty() {
        let levels = synopsis.as_ref().map_or_default(security_levels);
        if !levels.is_empty() {
            drop(arguments.insert("level".to_owned(), ValueType::Keyword(levels)));
        }
    }
    let mut parse_warnings = Vec::new();
    if is_leaf && synopsis.is_none() {
        parse_warnings.push("missing or truncated Synopsis".to_owned());
    }
    for name in &argument_names {
        if !arguments.contains_key(name) {
            let exception = UntypedArgument {
                path: path.clone(),
                name: name.clone(),
            };
            if untyped_allowlist.contains(&exception) {
                parse_warnings.push(format!("argument {name} has no recognized type"));
            } else {
                drop(arguments.insert(name.clone(), inferred_value_type(name)));
            }
        }
    }
    let since = first_history_version(lines).unwrap_or_else(|| entry.version.clone());
    let kind = if path == "show" || path.starts_with("show ") {
        CommandKind::Show
    } else if change_settings {
        CommandKind::Setting
    } else {
        CommandKind::Action
    };
    let mut models = BTreeSet::new();
    let _inserted = models.insert(entry.model.clone());
    Command {
        path,
        models,
        since,
        page,
        source_url: entry.url.clone(),
        kind,
        prefix_no,
        multiple_input,
        change_settings,
        persists_immediately,
        group_entry: is_group,
        interface_type,
        context,
        synopsis,
        arguments,
        parse_warnings,
    }
}

/// Returns a one-line field value after its label.
fn field_value<'text>(lines: &'text [&str], label: &str) -> Option<&'text str> {
    lines.iter().find_map(|line| {
        let trimmed = line.trim_start();
        trimmed
            .strip_prefix(label)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

/// Collects a field's lines until the next structural label.
fn field_block(lines: &[&str], label: &str, stops: &[&str]) -> String {
    let mut collecting = false;
    let mut parts = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if !collecting {
            if let Some(first) = trimmed.strip_prefix(label) {
                collecting = true;
                if !first.trim().is_empty() {
                    parts.push(first.trim());
                }
            }
            continue;
        }
        if stops.iter().any(|stop| trimmed.starts_with(stop)) {
            break;
        }
        if !trimmed.is_empty() && !is_page_furniture(trimmed) {
            parts.push(trimmed);
        }
    }
    parts.join(" ")
}

/// Whether a line is a repeated page header/footer rather than field data.
fn is_page_furniture(line: &str) -> bool {
    line.contains("Command Reference Guide")
        || line.starts_with("Chapter 3 ")
        || line.starts_with("Appendix C ")
}

/// Whether a section contains a Synopsis label.
fn has_synopsis(lines: &[&str]) -> bool {
    lines
        .iter()
        .any(|line| line.trim_start().starts_with("Synopsis"))
}

/// Collects synopsis lines through the next structural section.
fn synopsis_block(lines: &[&str]) -> Option<String> {
    let text = field_block(lines, "Synopsis", &["Arguments", "Example", "History"]);
    (!text.is_empty()).then_some(text)
}

/// Extracts every unique `‹name›` marker from a synopsis.
fn argument_names(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut rest = text;
    while let Some((_, after_open)) = rest.split_once('\u{2039}') {
        let Some((name, after_close)) = after_open.split_once('\u{203a}') else {
            break;
        };
        if !name.is_empty() {
            let _inserted = names.insert(name.to_owned());
        }
        rest = after_close;
    }
    names
}

/// Recursive-descent synopsis parser over brackets, groups, alternatives, arguments,
/// and literal keywords.
fn parse_synopsis(text: &str) -> Option<Grammar> {
    let syntax = text
        .split('>')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .filter(|part| !part.starts_with("(config") && !part.starts_with("(nvox"))
        .collect::<Vec<_>>()
        .join(" ");
    let tokens = tokenize_synopsis(&syntax);
    let mut parser = GrammarParser {
        tokens: &tokens,
        cursor: 0,
    };
    let grammar = parser.parse_alternative(None)?;
    (parser.cursor == tokens.len()).then_some(grammar)
}

/// One internal grammar token.
#[derive(Debug)]
enum Token {
    /// `[`.
    OpenOptional,
    /// `]`.
    CloseOptional,
    /// `(`.
    OpenGroup,
    /// `)`.
    CloseGroup,
    /// `|`.
    Pipe,
    /// `‹name›`.
    Argument(String),
    /// Literal keyword.
    Keyword(String),
}

/// Tokenizes synopsis punctuation and words.
fn tokenize_synopsis(text: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut argument = String::new();
    let mut in_argument = false;
    for character in text.chars() {
        if in_argument {
            if character == '\u{203a}' {
                if !argument.is_empty() {
                    tokens.push(Token::Argument(take(&mut argument)));
                }
                in_argument = false;
            } else {
                argument.push(character);
            }
            continue;
        }
        match character {
            '\u{2039}' => {
                push_keyword(&mut tokens, &mut word);
                in_argument = true;
            }
            '[' => {
                push_keyword(&mut tokens, &mut word);
                tokens.push(Token::OpenOptional);
            }
            ']' => {
                push_keyword(&mut tokens, &mut word);
                tokens.push(Token::CloseOptional);
            }
            '(' => {
                push_keyword(&mut tokens, &mut word);
                tokens.push(Token::OpenGroup);
            }
            ')' => {
                push_keyword(&mut tokens, &mut word);
                tokens.push(Token::CloseGroup);
            }
            '|' => {
                push_keyword(&mut tokens, &mut word);
                tokens.push(Token::Pipe);
            }
            value if value.is_whitespace() => push_keyword(&mut tokens, &mut word),
            value => word.push(value),
        }
    }
    push_keyword(&mut tokens, &mut word);
    tokens
}

/// Flushes one literal token.
fn push_keyword(tokens: &mut Vec<Token>, word: &mut String) {
    if !word.is_empty() {
        let value = take(word);
        if value != "no" {
            tokens.push(Token::Keyword(value));
        }
    }
}

/// Recursive parser state.
struct GrammarParser<'tokens> {
    /// Input tokens.
    tokens: &'tokens [Token],
    /// Next token index.
    cursor: usize,
}

impl GrammarParser<'_> {
    /// Parses alternatives until `closing` or end of input.
    fn parse_alternative(&mut self, closing: Option<char>) -> Option<Grammar> {
        let mut alternatives = vec![self.parse_sequence(closing)?];
        while matches!(self.tokens.get(self.cursor), Some(Token::Pipe)) {
            self.cursor = self.cursor.saturating_add(1);
            alternatives.push(self.parse_sequence(closing)?);
        }
        if alternatives.len() == 1 {
            alternatives.pop()
        } else {
            Some(Grammar::Alternative(alternatives))
        }
    }

    /// Parses an ordered sequence.
    fn parse_sequence(&mut self, closing: Option<char>) -> Option<Grammar> {
        let mut nodes = Vec::new();
        loop {
            match self.tokens.get(self.cursor) {
                None | Some(Token::Pipe) => break,
                Some(Token::CloseOptional) if closing == Some(']') => break,
                Some(Token::CloseGroup) if closing == Some(')') => break,
                Some(Token::CloseOptional | Token::CloseGroup) => return None,
                Some(Token::OpenOptional) => {
                    self.cursor = self.cursor.saturating_add(1);
                    let node = self.parse_alternative(Some(']'))?;
                    if !matches!(self.tokens.get(self.cursor), Some(Token::CloseOptional)) {
                        return None;
                    }
                    self.cursor = self.cursor.saturating_add(1);
                    nodes.push(Grammar::Optional(Box::new(node)));
                }
                Some(Token::OpenGroup) => {
                    self.cursor = self.cursor.saturating_add(1);
                    let node = self.parse_alternative(Some(')'))?;
                    if !matches!(self.tokens.get(self.cursor), Some(Token::CloseGroup)) {
                        return None;
                    }
                    self.cursor = self.cursor.saturating_add(1);
                    nodes.push(Grammar::Group(Box::new(node)));
                }
                Some(Token::Argument(name)) => {
                    nodes.push(Grammar::Argument(name.clone()));
                    self.cursor = self.cursor.saturating_add(1);
                }
                Some(Token::Keyword(word)) => {
                    nodes.push(Grammar::Keyword(word.clone()));
                    self.cursor = self.cursor.saturating_add(1);
                }
            }
        }
        match nodes.len() {
            0 => None,
            1 => nodes.pop(),
            _ => Some(Grammar::Sequence(nodes)),
        }
    }
}

/// Parses the Arguments table for names present in the synopsis.
fn parse_arguments(lines: &[&str], expected: &BTreeSet<String>) -> BTreeMap<String, ValueType> {
    let Some(start) = lines
        .iter()
        .position(|line| line.trim_start().starts_with("Arguments"))
    else {
        return BTreeMap::new();
    };
    let end = lines
        .iter()
        .enumerate()
        .skip(start.saturating_add(1))
        .find_map(|(index, line)| {
            let trimmed = line.trim_start();
            (trimmed.starts_with("Example") || trimmed.starts_with("History")).then_some(index)
        })
        .unwrap_or(lines.len());
    let mut result = BTreeMap::new();
    let mut current_keyword: Option<(String, usize)> = None;
    let table = lines.get(start.saturating_add(1)..end).unwrap_or_default();
    for line in table {
        let columns = split_columns(line);
        if columns
            .first()
            .is_some_and(|value| matches!(*value, "Argument" | "Arguments"))
        {
            if let Some(column) = line.find("Value")
                && let Some((_, value_column)) = &mut current_keyword
            {
                *value_column = column;
            }
            continue;
        }
        if columns.is_empty() || is_page_furniture(line.trim()) {
            continue;
        }
        if let Some((name, value, value_column)) = argument_row(line, expected) {
            if result.contains_key(name) {
                continue;
            }
            let parsed = parse_value_type(name, value);
            if matches!(parsed, ValueType::Keyword(_)) {
                current_keyword = Some((name.to_owned(), value_column));
            } else {
                current_keyword = None;
            }
            drop(result.insert(name.to_owned(), parsed));
        } else if let (Some((name, value_column)), Some(literals)) =
            (&current_keyword, columns.first())
            && leading_spaces(line).abs_diff(*value_column) <= 8
            && argument_row(line, expected).is_none_or(|(candidate, _, _)| {
                candidate == name && !result.contains_key(candidate)
            })
            && let Some(ValueType::Keyword(values)) = result.get_mut(name)
        {
            values.extend(keyword_literals(literals));
        } else {
            drop(columns);
        }
    }
    result
}

/// Recovers argument and value columns even where Poppler leaves only one separating space.
fn argument_row<'text>(
    line: &'text str,
    expected: &'text BTreeSet<String>,
) -> Option<(&'text str, &'text str, usize)> {
    let trimmed = line.trim();
    let name = expected
        .iter()
        .filter(|candidate| {
            trimmed
                .strip_prefix(candidate.as_str())
                .is_some_and(|rest| rest.chars().next().is_some_and(char::is_whitespace))
        })
        .max_by_key(|candidate| candidate.len())?;
    let name_column = line.find(name.as_str())?;
    if name_column > 32 {
        return None;
    }
    let after_name = trimmed.strip_prefix(name.as_str())?;
    let rest = after_name.trim_start();
    let value_column = leading_spaces(line)
        .saturating_add(name.len())
        .saturating_add(after_name.len().saturating_sub(rest.len()));
    let value = [
        "IP address/mask",
        "MAC address",
        "IP address",
        "IP-mask",
        "Interface",
        "Filename",
        "Password",
        "Boolean",
        "Integer",
        "String",
    ]
    .into_iter()
    .find(|candidate| rest.starts_with(candidate))
    .or_else(|| rest.split_whitespace().next())?;
    Some((name, value, value_column))
}

/// Returns the value-column offset of a layout-preserving table row.
fn leading_spaces(line: &str) -> usize {
    line.len().saturating_sub(line.trim_start().len())
}

/// Splits a layout-preserving table row on runs of at least two spaces.
fn split_columns(line: &str) -> Vec<&str> {
    line.trim()
        .split("  ")
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect()
}

/// Maps one table value cell into the closed type set.
fn parse_value_type(name: &str, value: &str) -> ValueType {
    match (name, value) {
        ("password", "String") | (_, "Password") => ValueType::Password,
        (_, "String") => ValueType::String,
        (_, "Integer") => ValueType::Integer,
        (_, "IP address") => ValueType::IpAddress,
        (_, "IP-mask") => ValueType::IpMask,
        (_, "IP address/mask") => ValueType::IpAddressMask,
        (_, "MAC address") => ValueType::MacAddress,
        (_, "Interface") => ValueType::Interface,
        (_, "Policy" | "Schedule") => ValueType::ObjectName,
        (_, "Filename") => ValueType::Filename,
        (_, "Boolean") => ValueType::Boolean,
        (_, "Keyword") => ValueType::Keyword(BTreeSet::from([name.to_owned()])),
        (_, ambiguous @ "Prefix") => match name {
            "address" | "gateway" | "host" | "network" | "to-address" => ValueType::IpAddress,
            "mask" => ValueType::IpMask,
            "prefix" => ValueType::IpAddressMask,
            "interface" | "to-interface" => ValueType::Interface,
            _ => ValueType::Keyword(BTreeSet::from([ambiguous.to_owned()])),
        },
        (_, literals) => ValueType::Keyword(keyword_literals(literals)),
    }
}

/// Conservatively types a synopsis argument when its manual table row is absent or unreadable.
fn inferred_value_type(name: &str) -> ValueType {
    if name.contains("interface") {
        ValueType::Interface
    } else if matches!(
        name,
        "count"
            | "days"
            | "group"
            | "hours"
            | "interval"
            | "metric"
            | "minutes"
            | "pause"
            | "pcp"
            | "priority"
            | "proceed"
            | "seconds"
            | "vga-clamp"
    ) {
        ValueType::Integer
    } else {
        ValueType::String
    }
}

/// Collects request keywords represented only as security-level synopsis alternatives.
fn security_levels(grammar: &Grammar) -> BTreeSet<String> {
    match grammar {
        Grammar::Sequence(nodes) | Grammar::Alternative(nodes) => {
            nodes.iter().flat_map(security_levels).collect()
        }
        Grammar::Optional(node) | Grammar::Group(node) => security_levels(node),
        Grammar::Keyword(value) if matches!(value.as_str(), "public" | "private" | "protected") => {
            BTreeSet::from([value.clone()])
        }
        Grammar::Argument(_) | Grammar::Keyword(_) => BTreeSet::new(),
    }
}

/// Parses comma-separated keyword alternatives from one value cell.
fn keyword_literals(value: &str) -> BTreeSet<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|literal| is_literal(literal))
        .map(str::to_owned)
        .collect()
}

/// Conservative literal check for continuation rows in keyword tables.
fn is_literal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.ends_with(['.', ',', ';', ':'])
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "a" | "an"
                | "are"
                | "becomes"
                | "for"
                | "is"
                | "length"
                | "of"
                | "the"
                | "there"
                | "to"
                | "with"
        )
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '/' | '.' | '@')
        })
}

/// Reads the first version value after a History heading.
fn first_history_version(lines: &[&str]) -> Option<String> {
    let start = lines
        .iter()
        .position(|line| line.trim_start().starts_with("History"))?;
    lines.iter().skip(start.saturating_add(1)).find_map(|line| {
        split_columns(line)
            .into_iter()
            .find(|column| {
                column
                    .chars()
                    .next()
                    .is_some_and(|character| character.is_ascii_digit())
                    && column
                        .chars()
                        .all(|character| character.is_ascii_digit() || character == '.')
            })
            .map(str::to_owned)
    })
}

/// Unions a model command into the command-path map.
fn merge_command(union: &mut BTreeMap<String, Command>, command: Command) {
    match union.get_mut(&command.path) {
        Some(existing) => {
            existing.models.extend(command.models);
            if existing.synopsis.is_none() && command.synopsis.is_some() {
                existing.synopsis = command.synopsis;
                existing.arguments = command.arguments;
                existing.parse_warnings = command.parse_warnings;
            }
            existing.prefix_no |= command.prefix_no;
            existing.multiple_input |= command.multiple_input;
            existing.change_settings |= command.change_settings;
            existing.persists_immediately |= command.persists_immediately;
            if existing.interface_type.is_none() {
                existing.interface_type = command.interface_type;
            }
            existing.group_entry |= command.group_entry;
            if existing.context.is_none() {
                existing.context = command.context;
            }
        }
        None => {
            drop(union.insert(command.path.clone(), command));
        }
    }
}

/// Writes group files and index, returning the ordered group names.
///
/// # Errors
///
/// Returns an output error when a catalog directory or JSON artifact cannot be written.
fn write_catalog(
    root: &Path,
    version: &str,
    union: &BTreeMap<String, Command>,
    hashes: &BTreeMap<String, String>,
    leaf_count: usize,
    synopsis_count: usize,
    coverage: usize,
) -> Result<Vec<String>, GateError> {
    let output_dir = root.join("catalog").join(version);
    fs::create_dir_all(&output_dir).map_err(|source| GateError::Write {
        path: output_dir.clone(),
        detail: source.to_string(),
    })?;
    remove_old_json(&output_dir)?;
    let mut grouped = BTreeMap::<String, Vec<&Command>>::new();
    for command in union.values() {
        let group = command
            .path
            .split_whitespace()
            .next()
            .unwrap_or("core")
            .to_owned();
        grouped.entry(group).or_default().push(command);
    }
    let file_groups: Vec<String> = grouped.keys().cloned().collect();
    for (group, commands) in grouped {
        let file = GroupFile {
            version,
            group: &group,
            commands,
        };
        let path = output_dir.join(format!("{group}.json"));
        write_json(&path, &file)?;
        enforce_size(&path)?;
    }
    let index = Index {
        version: version.to_owned(),
        generator_version: GENERATOR_VERSION,
        groups: union
            .values()
            .filter(|command| command.group_entry)
            .map(|command| command.path.clone())
            .collect(),
        file_groups: file_groups.clone(),
        command_count: union.len(),
        reference_leaf_count: leaf_count,
        synopsis_count,
        synopsis_coverage_percent: coverage,
        source_sha256s: hashes.clone(),
    };
    let index_path = output_dir.join("index.json");
    write_json(&index_path, &index)?;
    enforce_size(&index_path)?;
    Ok(file_groups)
}

/// Removes generated JSON files before rebuilding one version.
///
/// # Errors
///
/// Returns an I/O error when the directory cannot be listed or an old JSON file removed.
fn remove_old_json(directory: &Path) -> Result<(), GateError> {
    let entries = fs::read_dir(directory).map_err(|source| GateError::Read {
        path: directory.to_path_buf(),
        source,
    })?;
    for directory_entry in entries {
        let entry = directory_entry.map_err(|source| GateError::Read {
            path: directory.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            fs::remove_file(&path).map_err(|source| GateError::Write {
                path,
                detail: source.to_string(),
            })?;
        }
    }
    Ok(())
}

/// Pretty-serializes one JSON artifact with a trailing newline.
///
/// # Errors
///
/// Returns an output error when serialization or writing fails.
fn write_json<T>(path: &Path, value: &T) -> Result<(), GateError>
where
    T: Serialize + ?Sized,
{
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|source| GateError::Write {
        path: path.to_path_buf(),
        detail: source.to_string(),
    })?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|source| GateError::Write {
        path: path.to_path_buf(),
        detail: source.to_string(),
    })
}

/// Enforces the committed artifact size ceiling.
///
/// # Errors
///
/// Returns an input error when metadata is unavailable or the file exceeds the ceiling.
fn enforce_size(path: &Path) -> Result<(), GateError> {
    let size = fs::metadata(path)
        .map_err(|source| GateError::Read {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if size >= MAX_FILE_BYTES {
        return Err(command_error(
            "catalog build",
            format!(
                "{} is {size} bytes; limit is below {MAX_FILE_BYTES}",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Regenerates the Rust include table from every committed version directory.
///
/// # Errors
///
/// Returns an I/O or path error when catalog files cannot be enumerated or output cannot be written.
fn write_generated(root: &Path) -> Result<(), GateError> {
    let mut files = Vec::<PathBuf>::new();
    for version in ["4.3", "5.0", "5.1"] {
        let directory = root.join("catalog").join(version);
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for directory_entry in entries {
            let entry = directory_entry.map_err(|source| GateError::Read {
                path: directory.clone(),
                source,
            })?;
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                files.push(path);
            }
        }
    }
    files.sort();
    let mut generated = String::from(
        "// generated by cargo xtask catalog build - do not edit\n\n/// Embedded catalog JSON files as `(relative_path, contents)`.\npub static FILES: &[(&str, &str)] = &[\n",
    );
    for path in files {
        let relative = path.strip_prefix(root).map_err(|source| {
            command_error(
                "catalog build",
                format!("cannot relativize {}: {source}", path.display()),
            )
        })?;
        let relative_text = relative.to_string_lossy().replace('\\', "/");
        write!(
            generated,
            "    (\n        \"{relative_text}\",\n        include_str!(concat!(\n            env!(\"CARGO_MANIFEST_DIR\"),\n            \"/../../{relative_text}\"\n        )),\n    ),\n"
        )
        .map_err(|source| GateError::Write {
            path: root.join("crates/kcc-catalog/src/generated.rs"),
            detail: source.to_string(),
        })?;
    }
    generated.push_str("];\n");
    let path = root.join("crates/kcc-catalog/src/generated.rs");
    fs::write(&path, generated).map_err(|source| GateError::Write {
        path,
        detail: source.to_string(),
    })
}

/// Builds a command-style gate error.
fn command_error(program: &str, detail: String) -> GateError {
    GateError::Command {
        program: program.to_owned(),
        detail,
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod committed_tests;
#[cfg(test)]
mod expected;
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests;
