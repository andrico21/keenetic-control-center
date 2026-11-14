//! `i18n-gen` and `i18n-check`: the Fluent key generator and the catalog completeness gate.
//!
//! `i18n-gen` writes `crates/kcc-i18n/src/keys.rs` with one constant per message of
//! `locales/en/*.ftl`. `i18n-check` compares every locale with English: same files, same
//! message ids, same variables per message, no empty values, valid Fluent syntax, and
//! the machine-translation header on every non-English file. Against the committed
//! catalogs it also fails when `keys.rs` is stale or a message is used by no source
//! under `crates/` (see [`unused`]).

use alloc::collections::{BTreeMap, BTreeSet};
use std::{fs, io, path::Path};

use fluent_syntax::{
    ast::{CallArguments, Entry, Expression, InlineExpression, Pattern, PatternElement},
    parser,
};

use crate::{Verdict, failure::GateError};

mod unused;

/// Catalog directory, relative to the repository root.
const LOCALES_DIR: &str = "crates/kcc-i18n/locales";

/// Generated key module, relative to the repository root.
const KEYS_RS: &str = "crates/kcc-i18n/src/keys.rs";

/// The source-of-truth locale.
const SOURCE_LOCALE: &str = "en";

/// Every locale that must have a catalog.
const REQUIRED_LOCALES: [&str; 6] = ["en", "ru", "uk", "de", "be", "kk"];

/// First line of every non-English `.ftl` file.
const REVIEW_HEADER: &str = "# Machine-assisted translation - native review pending";

/// rustfmt's default maximum line width, which the generated file must respect.
const MAX_WIDTH: usize = 100;

/// One message of a parsed `.ftl` file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Message {
    /// The message id.
    id: String,
    /// Every variable referenced by the value or the attributes.
    variables: BTreeSet<String>,
    /// Whether the value and every attribute are blank.
    empty: bool,
}

/// A parsed `.ftl` file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Catalog {
    /// Messages in file order.
    messages: Vec<Message>,
    /// Syntax errors as `line N: description`.
    syntax_errors: Vec<String>,
    /// Whether the first line is [`REVIEW_HEADER`].
    has_review_header: bool,
}

/// Runs `i18n-gen`: regenerates `keys.rs` from the committed English catalog.
///
/// # Errors
///
/// Returns a [`GateError`] when a catalog cannot be read or `keys.rs` cannot be written.
pub(crate) fn generate<W>(root: &Path, out: &mut W) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    let english = root.join(LOCALES_DIR).join(SOURCE_LOCALE);
    let Some(text) = render_keys(&english, out)? else {
        writeln!(out, "i18n-gen: FAILED, fix the English catalog first")?;
        return Ok(Verdict::Fail);
    };
    let path = root.join(KEYS_RS);
    fs::write(&path, text).map_err(|source| GateError::Write {
        path: path.clone(),
        detail: source.to_string(),
    })?;
    writeln!(out, "i18n-gen: wrote {KEYS_RS}")?;
    Ok(Verdict::Pass)
}

/// Runs `i18n-check` on `locales_dir` (default: the committed catalogs).
///
/// # Errors
///
/// Returns a [`GateError`] when a catalog directory or file cannot be read.
pub(crate) fn check<W>(
    root: &Path,
    locales_dir: Option<&Path>,
    out: &mut W,
) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    let dir = locales_dir.map_or_else(|| root.join(LOCALES_DIR), Path::to_path_buf);
    let mut problems = Vec::new();
    let source = load_locale(&dir.join(SOURCE_LOCALE))?;
    check_locale(SOURCE_LOCALE, &source, None, &mut problems);
    let mut locales: BTreeSet<String> =
        REQUIRED_LOCALES.iter().map(|&tag| tag.to_owned()).collect();
    locales.extend(subdirectories(&dir)?);
    for locale in locales.iter().filter(|tag| *tag != SOURCE_LOCALE) {
        let path = dir.join(locale);
        if path.is_dir() {
            let catalog = load_locale(&path)?;
            check_locale(locale, &catalog, Some(&source), &mut problems);
        } else {
            problems.push(format!("{locale}: missing locale directory"));
        }
    }
    if locales_dir.is_none() {
        check_keys_fresh(root, &mut problems, out)?;
        unused::check_unused(root, &source, &mut problems)?;
    }
    for problem in &problems {
        writeln!(out, "{problem}")?;
    }
    writeln!(
        out,
        "i18n-check: {} problem(s) across {} locale(s)",
        problems.len(),
        locales.len()
    )?;
    if problems.is_empty() {
        Ok(Verdict::Pass)
    } else {
        writeln!(out, "i18n-check: FAILED")?;
        Ok(Verdict::Fail)
    }
}

/// Adds a problem when the committed `keys.rs` differs from what `i18n-gen` writes.
///
/// # Errors
///
/// Returns a [`GateError`] when the English catalog or `keys.rs` cannot be read.
fn check_keys_fresh<W>(
    root: &Path,
    problems: &mut Vec<String>,
    out: &mut W,
) -> Result<(), GateError>
where
    W: io::Write,
{
    let english = root.join(LOCALES_DIR).join(SOURCE_LOCALE);
    let Some(expected) = render_keys(&english, out)? else {
        return Ok(());
    };
    let path = root.join(KEYS_RS);
    let actual = fs::read_to_string(&path).map_err(|source| GateError::Read { path, source })?;
    if actual != expected {
        problems.push(format!("{KEYS_RS}: stale, run `cargo xtask i18n-gen`"));
    }
    Ok(())
}

/// Parses every `.ftl` file of one locale directory, keyed by file name.
///
/// # Errors
///
/// Returns [`GateError::Read`] when the directory or a file cannot be read.
fn load_locale(dir: &Path) -> Result<BTreeMap<String, Catalog>, GateError> {
    let mut catalogs = BTreeMap::new();
    let entries = fs::read_dir(dir).map_err(|source| GateError::Read {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let path = entry
            .map_err(|source| GateError::Read {
                path: dir.to_path_buf(),
                source,
            })?
            .path();
        let is_ftl = path.extension().is_some_and(|extension| extension == "ftl");
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if is_ftl && path.is_file() {
            let text = fs::read_to_string(&path).map_err(|source| GateError::Read {
                path: path.clone(),
                source,
            })?;
            drop(catalogs.insert(name.to_owned(), parse_catalog(&text)));
        }
    }
    Ok(catalogs)
}

/// Names of the subdirectories of `dir`.
///
/// # Errors
///
/// Returns [`GateError::Read`] when `dir` cannot be listed.
fn subdirectories(dir: &Path) -> Result<Vec<String>, GateError> {
    let read_error = |source| GateError::Read {
        path: dir.to_path_buf(),
        source,
    };
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).map_err(read_error)? {
        let path = entry.map_err(read_error)?.path();
        if let Some(name) = path.file_name().and_then(|name| name.to_str())
            && path.is_dir()
        {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

/// Appends every problem of one locale to `problems`; `source` is `None` for English.
fn check_locale(
    locale: &str,
    catalogs: &BTreeMap<String, Catalog>,
    source: Option<&BTreeMap<String, Catalog>>,
    problems: &mut Vec<String>,
) {
    let mut seen = BTreeMap::<&str, &str>::new();
    for (file, catalog) in catalogs {
        let at = format!("{locale}/{file}");
        for error in &catalog.syntax_errors {
            problems.push(format!("{at}: invalid Fluent syntax, {error}"));
        }
        if source.is_some() && !catalog.has_review_header {
            problems.push(format!("{at}: first line must be `{REVIEW_HEADER}`"));
        }
        for message in &catalog.messages {
            if message.empty {
                problems.push(format!("{at}: empty value for {}", message.id));
            }
            if let Some(first) = seen.insert(&message.id, file) {
                problems.push(format!(
                    "{at}: duplicate key {} (also in {first})",
                    message.id
                ));
            }
        }
        if let Some(reference) = source {
            match reference.get(file) {
                Some(expected) => compare(&at, expected, catalog, problems),
                None => problems.push(format!("{at}: extra file, not in {SOURCE_LOCALE}/")),
            }
        }
    }
    for file in source.into_iter().flat_map(BTreeMap::keys) {
        if !catalogs.contains_key(file) {
            problems.push(format!("{locale}/{file}: missing file"));
        }
    }
}

/// Compares one translated file with its English counterpart.
fn compare(at: &str, expected: &Catalog, actual: &Catalog, problems: &mut Vec<String>) {
    let translated: BTreeMap<&str, &Message> = actual
        .messages
        .iter()
        .map(|message| (message.id.as_str(), message))
        .collect();
    let english: BTreeSet<&str> = expected
        .messages
        .iter()
        .map(|message| message.id.as_str())
        .collect();
    for message in &expected.messages {
        match translated.get(message.id.as_str()) {
            None => problems.push(format!("{at}: missing key {}", message.id)),
            Some(found) if found.variables != message.variables => problems.push(format!(
                "{at}: key {} uses variables {{{}}}, {SOURCE_LOCALE} uses {{{}}}",
                message.id,
                join(&found.variables),
                join(&message.variables)
            )),
            Some(_) => {}
        }
    }
    for message in &actual.messages {
        if !english.contains(message.id.as_str()) {
            problems.push(format!("{at}: extra key {}", message.id));
        }
    }
}

/// Joins variable names as `$a, $b`.
fn join(variables: &BTreeSet<String>) -> String {
    variables
        .iter()
        .map(|name| format!("${name}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Parses one `.ftl` file, keeping messages and syntax errors.
fn parse_catalog(text: &str) -> Catalog {
    let (resource, errors) = match parser::parse(text) {
        Ok(resource) => (resource, Vec::new()),
        Err((resource, errors)) => (resource, errors),
    };
    let syntax_errors = errors
        .iter()
        .map(|error| format!("line {}: {error}", line_of(text, error.pos.start)))
        .collect();
    let messages = resource
        .body
        .iter()
        .filter_map(|entry| match entry {
            Entry::Message(message) => {
                let mut variables = BTreeSet::new();
                let mut empty = true;
                let patterns = message
                    .value
                    .iter()
                    .chain(message.attributes.iter().map(|attribute| &attribute.value));
                for pattern in patterns {
                    collect_pattern(pattern, &mut variables);
                    empty &= is_blank(pattern);
                }
                Some(Message {
                    id: message.id.name.to_owned(),
                    variables,
                    empty,
                })
            }
            Entry::Term(_)
            | Entry::Comment(_)
            | Entry::GroupComment(_)
            | Entry::ResourceComment(_)
            | Entry::Junk { content: _ } => None,
        })
        .collect();
    Catalog {
        messages,
        syntax_errors,
        has_review_header: text.lines().next() == Some(REVIEW_HEADER),
    }
}

/// The 1-based line containing byte `offset` of `text`.
fn line_of(text: &str, offset: usize) -> usize {
    let before = text.as_bytes().get(..offset).unwrap_or(text.as_bytes());
    before.split(|&byte| byte == b'\n').count()
}

/// Whether a pattern renders nothing but whitespace.
fn is_blank(pattern: &Pattern<&str>) -> bool {
    pattern.elements.iter().all(|element| match element {
        PatternElement::TextElement { value } => value.trim().is_empty(),
        PatternElement::Placeable { expression: _ } => false,
    })
}

/// Adds every variable referenced by `pattern` to `variables`.
fn collect_pattern(pattern: &Pattern<&str>, variables: &mut BTreeSet<String>) {
    for element in &pattern.elements {
        match element {
            PatternElement::Placeable { expression } => collect_expression(expression, variables),
            PatternElement::TextElement { value: _ } => {}
        }
    }
}

/// Adds every variable referenced by `expression` to `variables`.
fn collect_expression(expression: &Expression<&str>, variables: &mut BTreeSet<String>) {
    match expression {
        Expression::Select { selector, variants } => {
            collect_inline(selector, variables);
            for variant in variants {
                collect_pattern(&variant.value, variables);
            }
        }
        Expression::Inline(inline) => collect_inline(inline, variables),
    }
}

/// Adds every variable referenced by `inline` to `variables`.
fn collect_inline(inline: &InlineExpression<&str>, variables: &mut BTreeSet<String>) {
    match inline {
        InlineExpression::VariableReference { id } => {
            let _: bool = variables.insert(id.name.to_owned());
        }
        InlineExpression::Placeable { expression } => collect_expression(expression, variables),
        InlineExpression::FunctionReference { id: _, arguments } => {
            collect_arguments(arguments, variables);
        }
        InlineExpression::TermReference {
            id: _,
            attribute: _,
            arguments,
        } => {
            if let Some(call) = arguments {
                collect_arguments(call, variables);
            }
        }
        InlineExpression::StringLiteral { value: _ }
        | InlineExpression::NumberLiteral { value: _ }
        | InlineExpression::MessageReference {
            id: _,
            attribute: _,
        } => {}
    }
}

/// Adds every variable referenced by call arguments to `variables`.
fn collect_arguments(arguments: &CallArguments<&str>, variables: &mut BTreeSet<String>) {
    for positional in &arguments.positional {
        collect_inline(positional, variables);
    }
    for named in &arguments.named {
        collect_inline(&named.value, variables);
    }
}

/// Renders `keys.rs` from the English catalog in `source`; prints the problems and
/// returns `None` when the catalog is invalid.
///
/// # Errors
///
/// Returns [`GateError::Read`] when the English catalog cannot be read.
fn render_keys<W>(source: &Path, out: &mut W) -> Result<Option<String>, GateError>
where
    W: io::Write,
{
    let catalogs = load_locale(source)?;
    let mut problems = Vec::new();
    check_locale(SOURCE_LOCALE, &catalogs, None, &mut problems);
    let mut names = BTreeMap::<String, String>::new();
    let mut text = String::from(
        "//! Message keys generated by `cargo xtask i18n-gen` from `locales/en/*.ftl`; do not edit.\n\
         \n\
         use crate::bundle::MessageKey;\n",
    );
    let mut all = Vec::new();
    for (file, catalog) in &catalogs {
        for message in &catalog.messages {
            let name = key_constant(&message.id);
            if let Some(previous) = names.insert(name.clone(), message.id.clone()) {
                problems.push(format!(
                    "{SOURCE_LOCALE}/{file}: key {} and {previous} both map to {name}",
                    message.id
                ));
            }
            push_constant(&mut text, file, &name, &message.id);
            all.push(name);
        }
    }
    let count = all.len().to_string();
    for piece in [
        "\n/// Every message key, in catalog order.\npub static ALL: [MessageKey; ",
        &count,
        "] = [\n",
    ] {
        text.push_str(piece);
    }
    for name in &all {
        for piece in ["    ", name, ",\n"] {
            text.push_str(piece);
        }
    }
    text.push_str("];\n");
    if problems.is_empty() {
        Ok(Some(text))
    } else {
        for problem in &problems {
            writeln!(out, "{problem}")?;
        }
        Ok(None)
    }
}

/// The generated constant name of a message id: upper case with `_` for `-`.
fn key_constant(id: &str) -> String {
    id.to_ascii_uppercase().replace('-', "_")
}

/// Appends one documented key constant, wrapped the way rustfmt would wrap it.
fn push_constant(text: &mut String, file: &str, name: &str, id: &str) {
    let head = format!("pub const {name}: MessageKey =");
    let tail = format!("MessageKey::new(\"{id}\");");
    let width = head.len().saturating_add(tail.len()).saturating_add(1);
    let separator = if width > MAX_WIDTH { "\n    " } else { " " };
    for piece in [
        "\n/// `", id, "` in `", file, "`.\n", &head, separator, &tail, "\n",
    ] {
        text.push_str(piece);
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;
    use std::fs;

    use super::{check, parse_catalog};
    use crate::Verdict;

    /// Fallible test result.
    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn variables_are_collected_from_selectors_and_variants() {
        let catalog = parse_catalog(
            "a = { $count ->\n    [one] { $name }\n   *[other] { NUMBER($total) }\n}\nb = \n    .title = { $x }\n",
        );
        let ids: Vec<_> = catalog
            .messages
            .iter()
            .map(|message| message.id.as_str())
            .collect();
        assert_eq!(ids, ["a", "b"], "both messages parsed");
        let first = catalog
            .messages
            .first()
            .map(|message| message.variables.clone());
        let expected = ["count", "name", "total"].map(str::to_owned).into();
        assert_eq!(
            first,
            Some(expected),
            "selector, variant and call arguments"
        );
        assert!(
            catalog.syntax_errors.is_empty(),
            "{:?}",
            catalog.syntax_errors
        );
    }

    #[test]
    fn syntax_errors_are_reported_with_lines() {
        let catalog = parse_catalog("ok = fine\n= broken\n");
        assert_eq!(catalog.syntax_errors.len(), 1, "one error");
        assert!(
            catalog
                .syntax_errors
                .iter()
                .all(|error| error.starts_with("line 2:")),
            "{:?}",
            catalog.syntax_errors
        );
    }

    #[test]
    fn check_reports_missing_extra_and_mismatched_keys() -> TestResult {
        let dir = tempfile::tempdir()?;
        let header = "# Machine-assisted translation - native review pending\n";
        for locale in ["en", "ru", "uk", "de", "be", "kk"] {
            fs::create_dir_all(dir.path().join(locale))?;
            let body = if locale == "en" {
                "a = A { $n }\nb = B\n".to_owned()
            } else {
                format!("{header}a = A {{ $n }}\nb = B\n")
            };
            fs::write(dir.path().join(locale).join("web.ftl"), body)?;
        }
        let mut report = Vec::new();
        assert_eq!(
            check(dir.path(), Some(dir.path()), &mut report)?,
            Verdict::Pass,
            "clean"
        );
        fs::write(
            dir.path().join("de").join("web.ftl"),
            format!("{header}a = A {{ $m }}\nc = C\n"),
        )?;
        fs::write(
            dir.path().join("kk").join("web.ftl"),
            "a = A { $n }\nb = B\n",
        )?;
        let mut failed = Vec::new();
        assert_eq!(
            check(dir.path(), Some(dir.path()), &mut failed)?,
            Verdict::Fail,
            "broken"
        );
        let text = String::from_utf8(failed)?;
        for expected in [
            "de/web.ftl: missing key b",
            "de/web.ftl: extra key c",
            "de/web.ftl: key a uses variables {$m}, en uses {$n}",
            "kk/web.ftl: first line must be",
        ] {
            assert!(text.contains(expected), "{expected} not in {text}");
        }
        Ok(())
    }
}
