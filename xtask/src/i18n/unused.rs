//! The unused-key check of `i18n-check`: a catalog message nothing refers to is dead text
//! in six locales and fails the gate.
//!
//! A key is used when its generated constant name appears as an identifier, or its id as
//! a quoted string literal, in a `.rs`, `.html` or `.js` file under `crates/`. The
//! generated `keys.rs` is skipped (its `ALL` list names every constant). No code builds
//! message ids at run time, so there is no dynamic-prefix rule: a key reached only
//! through a runtime-built id would have to be referenced by a literal.

use alloc::collections::{BTreeMap, BTreeSet};
use std::{fs, path::Path};

use super::{Catalog, KEYS_RS, LOCALES_DIR, SOURCE_LOCALE, key_constant};
use crate::failure::GateError;

/// Directory names never descended into.
const SKIP_DIRS: [&str; 2] = ["target", "node_modules"];

/// Source extensions that may refer to a key.
const SOURCE_EXTENSIONS: [&str; 3] = ["rs", "html", "js"];

/// Adds one problem per English message that no source under `root/crates` refers to.
///
/// # Errors
///
/// Returns [`GateError::Read`] when a source directory or file cannot be read.
pub(super) fn check_unused(
    root: &Path,
    english: &BTreeMap<String, Catalog>,
    problems: &mut Vec<String>,
) -> Result<(), GateError> {
    let mut sources = Vec::new();
    collect_sources(&root.join("crates"), &root.join(KEYS_RS), &mut sources)?;
    let identifiers = identifier_set(&sources);
    for (file, catalog) in english {
        let path = root.join(LOCALES_DIR).join(SOURCE_LOCALE).join(file);
        let text = fs::read_to_string(&path).map_err(|source| GateError::Read { path, source })?;
        for message in &catalog.messages {
            if !is_used(&message.id, &identifiers, &sources) {
                let line = definition_line(&text, &message.id);
                problems.push(format!(
                    "{SOURCE_LOCALE}/{file}:{line}: unused key {}, no `{}` or \"{}\" in crates/**/*.{{rs,html,js}}",
                    message.id,
                    key_constant(&message.id),
                    message.id,
                ));
            }
        }
    }
    Ok(())
}

/// Whether `id` is referenced by constant name or by quoted id.
fn is_used(id: &str, identifiers: &BTreeSet<&str>, sources: &[String]) -> bool {
    let name = key_constant(id);
    if identifiers.contains(name.as_str()) {
        return true;
    }
    let quoted = [format!("\"{id}\""), format!("'{id}'")];
    sources
        .iter()
        .any(|source| quoted.iter().any(|needle| source.contains(needle.as_str())))
}

/// Every identifier-shaped word (`[A-Za-z0-9_]+`) of every source.
fn identifier_set(sources: &[String]) -> BTreeSet<&str> {
    sources
        .iter()
        .flat_map(|source| {
            source
                .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                .filter(|word| !word.is_empty())
        })
        .collect()
}

/// The 1-based line of the English definition of `id`, or 1 when it is not found.
fn definition_line(text: &str, id: &str) -> usize {
    text.lines()
        .position(|line| {
            line.strip_prefix(id)
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        })
        .map_or(1, |index| index.saturating_add(1))
}

/// Appends the text of every source file under `dir`, except `skip`.
///
/// # Errors
///
/// Returns [`GateError::Read`] when a directory or file cannot be read.
fn collect_sources(dir: &Path, skip: &Path, sources: &mut Vec<String>) -> Result<(), GateError> {
    let read_err = |source| GateError::Read {
        path: dir.to_path_buf(),
        source,
    };
    for listed in fs::read_dir(dir).map_err(read_err)? {
        let entry = listed.map_err(read_err)?;
        let path = entry.path();
        if entry.file_type().map_err(read_err)?.is_dir() {
            let skipped = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| SKIP_DIRS.contains(&name));
            if !skipped {
                collect_sources(&path, skip, sources)?;
            }
        } else if path != skip
            && path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| SOURCE_EXTENSIONS.contains(&ext))
        {
            sources.push(
                fs::read_to_string(&path).map_err(|source| GateError::Read { path, source })?,
            );
        } else {
            // Not a directory and not a scanned source: nothing to read.
        }
    }
    Ok(())
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

    use tempfile::TempDir;

    use super::{check_unused, definition_line};
    use crate::i18n::{KEYS_RS, LOCALES_DIR, load_locale};

    /// Fallible test result.
    type TestResult = Result<(), Box<dyn Error>>;

    /// Writes `files` (relative path, text) under a fresh root with an English `web.ftl`
    /// of `a-one`, `b-two`, `c-three`, `d-four`; returns the problems `check_unused` reports.
    fn problems_for(files: &[(&str, &str)]) -> Result<Vec<String>, Box<dyn Error>> {
        let root: TempDir = tempfile::tempdir()?;
        let english = root.path().join(LOCALES_DIR).join("en");
        fs::create_dir_all(&english)?;
        fs::write(
            english.join("web.ftl"),
            "# heading\na-one = A\nb-two = B\nc-three = C\nd-four = D\n",
        )?;
        let mut all = vec![(
            KEYS_RS,
            "pub static ALL: [K; 4] = [A_ONE, B_TWO, C_THREE, D_FOUR];",
        )];
        all.extend_from_slice(files);
        for (path, text) in all {
            let target = root.path().join(path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(target, text)?;
        }
        let catalogs = load_locale(&english)?;
        let mut problems = Vec::new();
        check_unused(root.path(), &catalogs, &mut problems)?;
        Ok(problems)
    }

    #[test]
    fn identifier_literal_and_template_uses_count_and_keys_rs_does_not() -> TestResult {
        let problems = problems_for(&[
            (
                "crates/x/src/lib.rs",
                "fn f() { let _ = keys::A_ONE; let _ = \"b-two\"; }",
            ),
            ("crates/x/templates/p.html", "<p>{{ t(keys::C_THREE) }}</p>"),
        ])?;
        assert_eq!(problems.len(), 1, "only d-four is unused: {problems:?}");
        assert!(
            problems
                .iter()
                .all(|problem| problem.contains("web.ftl:5: unused key d-four")),
            "{problems:?}"
        );
        Ok(())
    }

    #[test]
    fn a_longer_identifier_does_not_use_a_shorter_key() -> TestResult {
        let problems = problems_for(&[(
            "crates/x/src/lib.rs",
            "const _: () = { let _ = A_ONE_MORE; let _ = B_TWO; let _ = C_THREE; let _ = D_FOUR; };",
        )])?;
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems
                .iter()
                .all(|problem| problem.contains("unused key a-one")),
            "{problems:?}"
        );
        Ok(())
    }

    #[test]
    fn definition_line_is_one_based() {
        assert_eq!(definition_line("# c\nx-y = 1\n", "x-y"), 2, "second line");
    }
}
