//! `allow-gate`: no `#[allow(..)]` or `#![allow(..)]` in project sources.
//!
//! Walks `crates/` and `xtask/src` (not `spikes/`) for `.rs` files. Comments, string
//! literals and char literals are blanked first, so a mention of the attribute in a doc
//! comment or a test fixture string is not a hit. An attribute counts when its body is
//! `allow(..)` or a `cfg_attr(..)` that applies `allow(..)`; whitespace inside the
//! attribute is ignored.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use crate::{Verdict, failure::GateError};

/// Directories scanned, relative to the repository root.
pub(crate) const SCAN_DIRS: [&str; 2] = ["crates", "xtask/src"];

/// Directory names never descended into.
const SKIP_DIRS: [&str; 1] = ["target"];

/// One forbidden attribute in a source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hit {
    /// 1-based line of the attribute's `#`.
    line: usize,
    /// The attribute with whitespace removed, e.g. `#[allow(dead_code)]`.
    attribute: String,
}

/// Runs the gate under `root`, printing `path:line: attribute` for every hit.
///
/// # Errors
///
/// Returns a [`GateError`] when a directory or file cannot be read.
pub(crate) fn run<W>(root: &Path, out: &mut W) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    let mut files = Vec::new();
    for dir in SCAN_DIRS {
        let path = root.join(dir);
        if path.is_dir() {
            collect_rust_files(&path, &mut files)?;
        }
    }
    files.sort();
    let mut total = 0_usize;
    for file in &files {
        let text = fs::read_to_string(file).map_err(|source| GateError::Read {
            path: file.clone(),
            source,
        })?;
        let shown = file.strip_prefix(root).unwrap_or(file);
        for hit in scan(&text) {
            total = total.saturating_add(1);
            writeln!(out, "{}:{}: {}", shown.display(), hit.line, hit.attribute)?;
        }
    }
    writeln!(
        out,
        "allow-gate: {total} allow attribute(s) in {} file(s)",
        files.len()
    )?;
    if total == 0 {
        Ok(Verdict::Pass)
    } else {
        writeln!(
            out,
            "allow-gate: FAILED, use #[expect(lint, reason = \"...\")] instead"
        )?;
        Ok(Verdict::Fail)
    }
}

/// Appends every `.rs` file under `dir` to `files`, recursively.
///
/// # Errors
///
/// Returns [`GateError::Read`] when a directory cannot be listed.
fn collect_rust_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), GateError> {
    let read_err = |source| GateError::Read {
        path: dir.to_path_buf(),
        source,
    };
    for listed in fs::read_dir(dir).map_err(read_err)? {
        let entry = listed.map_err(read_err)?;
        let path = entry.path();
        let kind = entry.file_type().map_err(read_err)?;
        if kind.is_dir() {
            let skipped = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| SKIP_DIRS.contains(&name));
            if !skipped {
                collect_rust_files(&path, files)?;
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        } else {
            // Not a directory and not Rust source: nothing to scan.
        }
    }
    Ok(())
}

/// Every forbidden attribute in `source`.
pub(crate) fn scan(source: &str) -> Vec<Hit> {
    let code: Vec<char> = blank_non_code(source).chars().collect();
    let mut hits = Vec::new();
    let mut line = 1_usize;
    for (pos, current) in code.iter().enumerate() {
        match *current {
            '\n' => line = line.saturating_add(1),
            '#' => {
                if let Some(attribute) = attribute_at(&code, pos)
                    && is_forbidden(&attribute)
                {
                    hits.push(Hit { line, attribute });
                }
            }
            _ => {}
        }
    }
    hits
}

/// Whether a whitespace-free attribute such as `#[allow(x)]` applies `allow`.
fn is_forbidden(attribute: &str) -> bool {
    let body = attribute
        .trim_start_matches('#')
        .trim_start_matches('!')
        .trim_start_matches('[');
    if body.starts_with("allow(") {
        return true;
    }
    body.starts_with("cfg_attr(")
        && body.match_indices("allow(").any(|(at, _)| {
            body.get(..at)
                .is_some_and(|before| before.ends_with([',', '(']))
        })
}

/// The attribute starting at the `#` at `pos`, with whitespace removed, or `None` when
/// `#` does not open an attribute.
fn attribute_at(code: &[char], pos: usize) -> Option<String> {
    let mut text = String::from("#");
    let mut depth = 0_usize;
    for current in code.get(pos.checked_add(1)?..)? {
        if current.is_whitespace() {
            continue;
        }
        match (*current, depth) {
            ('!', 0) if text == "#" => {}
            ('[', _) => depth = depth.checked_add(1)?,
            (']', 1) => {
                text.push(']');
                return Some(text);
            }
            (']', _) => depth = depth.checked_sub(1)?,
            (_, 0) => return None,
            _ => {}
        }
        text.push(*current);
    }
    None
}

/// Replaces comments, string literals and char literals with spaces, keeping newlines so
/// line numbers are unchanged.
fn blank_non_code(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut pos = 0_usize;
    while let Some(current) = chars.get(pos).copied() {
        let next = chars.get(pos.saturating_add(1)).copied();
        let end = match (current, next) {
            ('/', Some('/')) => Some(find_from(&chars, pos, '\n')),
            ('/', Some('*')) => Some(block_comment_end(&chars, pos)),
            ('"', _) => Some(string_end(&chars, pos)),
            ('r', _) => raw_string_end(&chars, pos),
            ('\'', _) => char_literal_end(&chars, pos),
            _ => None,
        };
        if let Some(stop) = end {
            for blanked in chars.get(pos..stop).unwrap_or_default() {
                out.push(if matches!(*blanked, '\n' | '\r') {
                    *blanked
                } else {
                    ' '
                });
            }
            pos = stop.max(pos.saturating_add(1));
        } else {
            out.push(current);
            pos = pos.saturating_add(1);
        }
    }
    out
}

/// Index of the first `target` at or after `pos`, or the end of input.
fn find_from(chars: &[char], pos: usize, target: char) -> usize {
    chars
        .iter()
        .skip(pos)
        .position(|current| *current == target)
        .map_or(chars.len(), |offset| pos.saturating_add(offset))
}

/// End (exclusive) of the possibly nested block comment opening at `pos`.
fn block_comment_end(chars: &[char], pos: usize) -> usize {
    let mut depth = 0_usize;
    let mut at = pos;
    while let Some(current) = chars.get(at).copied() {
        let next = chars.get(at.saturating_add(1)).copied();
        match (current, next) {
            ('/', Some('*')) => {
                depth = depth.saturating_add(1);
                at = at.saturating_add(2);
            }
            ('*', Some('/')) => {
                depth = depth.saturating_sub(1);
                at = at.saturating_add(2);
                if depth == 0 {
                    return at;
                }
            }
            _ => at = at.saturating_add(1),
        }
    }
    chars.len()
}

/// End (exclusive) of the escaped string literal whose opening quote is at `pos`.
fn string_end(chars: &[char], pos: usize) -> usize {
    let mut at = pos.saturating_add(1);
    while let Some(current) = chars.get(at).copied() {
        match current {
            '\\' => at = at.saturating_add(2),
            '"' => return at.saturating_add(1),
            _ => at = at.saturating_add(1),
        }
    }
    chars.len()
}

/// End (exclusive) of the raw string literal (`r"..."`, `r#"..."#`, also after a `b` or
/// `c` prefix) whose `r` is at `pos`, or `None` when `r` does not start one.
fn raw_string_end(chars: &[char], pos: usize) -> Option<usize> {
    let before = pos.checked_sub(1).and_then(|at| chars.get(at)).copied();
    let prefix_ok = match before {
        None => true,
        Some('b' | 'c') => pos
            .checked_sub(2)
            .and_then(|at| chars.get(at))
            .is_none_or(|prior| !is_ident(*prior)),
        Some(other) => !is_ident(other),
    };
    if !prefix_ok {
        return None;
    }
    let hashes = chars
        .iter()
        .skip(pos.saturating_add(1))
        .take_while(|current| **current == '#')
        .count();
    let quote = pos.saturating_add(1).saturating_add(hashes);
    if chars.get(quote).copied() != Some('"') {
        return None;
    }
    let mut at = quote.saturating_add(1);
    while let Some(current) = chars.get(at).copied() {
        let closing = chars
            .iter()
            .skip(at.saturating_add(1))
            .take(hashes)
            .filter(|next| **next == '#')
            .count();
        if current == '"' && closing == hashes {
            return Some(at.saturating_add(1).saturating_add(hashes));
        }
        at = at.saturating_add(1);
    }
    Some(chars.len())
}

/// End (exclusive) of the char literal opening at `pos`, or `None` for a lifetime.
fn char_literal_end(chars: &[char], pos: usize) -> Option<usize> {
    let first = chars.get(pos.saturating_add(1)).copied()?;
    if first == '\\' {
        let close = find_from(chars, pos.saturating_add(3), '\'');
        return Some(close.saturating_add(1).min(chars.len()));
    }
    (chars.get(pos.saturating_add(2)).copied() == Some('\'')).then(|| pos.saturating_add(3))
}

/// Whether `current` can continue an identifier.
fn is_ident(current: char) -> bool {
    current.is_alphanumeric() || current == '_'
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
    use std::{fs, path::Path};

    use tempfile::TempDir;

    use super::{run, scan};
    use crate::Verdict;

    /// Writes `text` to `root/relative`, creating parent directories.
    fn plant(root: &Path, relative: &str, text: &str) -> Result<(), Box<dyn Error>> {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, text)?;
        Ok(())
    }

    /// Lines reported by [`scan`] for `source`.
    fn lines(source: &str) -> Vec<usize> {
        scan(source).into_iter().map(|hit| hit.line).collect()
    }

    /// Outer, inner, spaced, multi-line and `cfg_attr` forms are all hits.
    #[test]
    fn attribute_forms_are_hits() {
        assert_eq!(lines("#[allow(dead_code)]\nfn a() {}\n"), [1]);
        assert_eq!(lines("fn a() {}\n#![allow(unused)]\n"), [2]);
        assert_eq!(lines("# [ allow ( dead_code ) ]\nfn a() {}\n"), [1]);
        assert_eq!(
            lines("#[\n  allow(\n    dead_code,\n  )\n]\nfn a() {}\n"),
            [1]
        );
        assert_eq!(
            lines("#[cfg_attr(test, allow(clippy::panic))]\nfn a() {}\n"),
            [1]
        );
        assert_eq!(lines("let a = 1;\r\n#[allow(x)]\r\nfn d() {}\r\n"), [2]);
    }

    /// Comments, strings, raw strings and other attributes are not hits.
    #[test]
    fn decoys_are_not_hits() {
        let decoys = concat!(
            "// #[allow(dead_code)]\n",
            "/* #[allow(x)] /* nested #[allow(y)] */ #[allow(z)] */\n",
            "/// ```\n/// #[allow(dead_code)]\n/// ```\n",
            "const S: &str = \"#[allow(dead_code)] \\\" #[allow(x)]\";\n",
            "const R: &str = r#\"#[allow(dead_code)] \" still raw\"#;\n",
            "const C: char = '\"'; const Q: char = '\\'';\n",
            "fn f<'a>(x: &'a str) -> &'a str { x }\n",
            "#[expect(dead_code, reason = \"#[allow(x)]\")]\n",
            "#[cfg_attr(test, expect(clippy::allow_attributes, reason = \"r\"))]\n",
            "#[derive(Debug)] struct Allow;\n",
        );
        assert_eq!(lines(decoys), Vec::<usize>::new());
        assert_eq!(lines(&format!("{decoys}#[allow(late)]\n")), [13]);
    }

    /// A planted allow under `crates/` fails with `path:line`; `spikes/` is not scanned.
    #[test]
    fn planted_allow_fails() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        plant(dir.path(), "crates/kcc-rci/src/lib.rs", "//! Doc.\n")?;
        plant(
            dir.path(),
            "crates/kcc-rci/src/tmp_allow.rs",
            "\n#[allow(dead_code)] fn x() {}\n",
        )?;
        plant(
            dir.path(),
            "xtask/src/main.rs",
            "#![allow(unused)]\nfn main() {}\n",
        )?;
        plant(
            dir.path(),
            "spikes/demo/src/lib.rs",
            "#[allow(dead_code)] fn y() {}\n",
        )?;
        plant(
            dir.path(),
            "crates/kcc-rci/target/debug/gen.rs",
            "#[allow(x)] fn z() {}\n",
        )?;
        let mut out = Vec::new();
        let verdict = run(dir.path(), &mut out)?;
        let report = String::from_utf8(out)?;
        assert_eq!(verdict, Verdict::Fail, "{report}");
        assert!(
            report.contains("crates/kcc-rci/src/tmp_allow.rs:2: #[allow(dead_code)]"),
            "{report}"
        );
        assert!(
            report.contains("xtask/src/main.rs:1: #![allow(unused)]"),
            "{report}"
        );
        assert!(!report.contains("spikes"), "{report}");
        assert!(!report.contains("target"), "{report}");
        Ok(())
    }

    /// A tree with only `expect` attributes passes.
    #[test]
    fn clean_tree_passes() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        plant(
            dir.path(),
            "crates/kcc/src/main.rs",
            "#[expect(dead_code, reason = \"fixture\")]\nfn x() {}\nfn main() {}\n",
        )?;
        let mut out = Vec::new();
        assert_eq!(run(dir.path(), &mut out)?, Verdict::Pass);
        Ok(())
    }
}
