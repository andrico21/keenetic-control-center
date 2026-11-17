//! `cancel-safety`: every async fn in non-test crate source states its cancel safety
//! (R-GUIDE section 5).
//!
//! Walks `crates/*/src` for `.rs` files, skipping test code: any path with a `tests`
//! component, files and directories of `#[cfg(test)] mod name;` declarations, and
//! braced `#[cfg(test)]` items (so `#[tokio::test]` fns need nothing). Every
//! `async fn` of any visibility (`pub`, `pub(crate)`, `pub(super)`, `pub(in ..)`,
//! private, trait items and trait-impl methods) needs a `// cancel-safe:` or
//! `// NOT cancel-safe:` comment, as a line or doc comment, in the comment and attribute
//! block directly above. Async blocks and closures are not fns and are not checked.

mod scan;

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use self::scan::{TestModule, Visibility};
use crate::{Verdict, allow_gate::collect_rust_files, failure::GateError};

/// Runs the gate under `root`, printing `path:line: visibility async fn name` for every
/// unannotated fn and the count checked per visibility.
///
/// # Errors
///
/// Returns a [`GateError`] when a directory or file cannot be read.
pub(crate) fn run<W>(root: &Path, out: &mut W) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    let sources = read_sources(root)?;
    let scans: Vec<_> = sources
        .iter()
        .map(|(path, text)| (path, scan::scan(text)))
        .collect();
    let skipped: Vec<PathBuf> = scans
        .iter()
        .flat_map(|(path, found)| test_module_paths(path, found.test_modules()))
        .collect();
    let mut checked = [0_usize; Visibility::ALL.len()];
    let mut total = 0_usize;
    for (path, found) in &scans {
        let is_test = path.components().any(|part| part.as_os_str() == "tests")
            || skipped
                .iter()
                .any(|skip| *path == skip || path.starts_with(skip));
        if is_test {
            continue;
        }
        let shown = path.strip_prefix(root).unwrap_or(path);
        for item in found.found() {
            let slot = Visibility::ALL
                .iter()
                .position(|visibility| *visibility == item.visibility());
            if let Some(count) = slot.and_then(|at| checked.get_mut(at)) {
                *count = count.saturating_add(1);
            }
            if !item.is_annotated() {
                total = total.saturating_add(1);
                writeln!(
                    out,
                    "{}:{}: {} async fn {}",
                    shown.display(),
                    item.line(),
                    item.visibility().label(),
                    item.name()
                )?;
            }
        }
    }
    let by_visibility: Vec<String> = Visibility::ALL
        .iter()
        .zip(checked)
        .map(|(visibility, count)| format!("{} {count}", visibility.label()))
        .collect();
    writeln!(
        out,
        "cancel-safety: {total} of {} async fn(s) lack a cancel-safety comment ({})",
        checked.iter().sum::<usize>(),
        by_visibility.join(", ")
    )?;
    if total == 0 {
        Ok(Verdict::Pass)
    } else {
        writeln!(
            out,
            "cancel-safety: FAILED, add `// cancel-safe: <reason>` or \
             `// NOT cancel-safe: <reason>` above each fn"
        )?;
        Ok(Verdict::Fail)
    }
}

/// Every `.rs` file under `crates/*/src` with its text, sorted by path.
///
/// # Errors
///
/// Returns [`GateError::Read`] when a directory or file cannot be read.
fn read_sources(root: &Path) -> Result<Vec<(PathBuf, String)>, GateError> {
    let crates = root.join("crates");
    let read_err = |source| GateError::Read {
        path: crates.clone(),
        source,
    };
    let mut files = Vec::new();
    for listed in fs::read_dir(&crates).map_err(read_err)? {
        let src = listed.map_err(read_err)?.path().join("src");
        if src.is_dir() {
            collect_rust_files(&src, &mut files)?;
        }
    }
    files.sort();
    files
        .into_iter()
        .map(|path| match fs::read_to_string(&path) {
            Ok(text) => Ok((path, text)),
            Err(source) => Err(GateError::Read { path, source }),
        })
        .collect()
}

/// The file and directory of each out-of-line test module declared in `path`; a
/// `#[path]` module is the named file, relative to the declaring file's directory.
fn test_module_paths(path: &Path, modules: &[TestModule]) -> Vec<PathBuf> {
    let Some(parent) = path.parent() else {
        return Vec::new();
    };
    let is_root = path
        .file_name()
        .is_some_and(|name| name == "lib.rs" || name == "main.rs" || name == "mod.rs");
    let dir = match path.file_stem() {
        Some(stem) if !is_root => parent.join(stem),
        Some(_) | None => parent.to_path_buf(),
    };
    modules
        .iter()
        .flat_map(|module| {
            module.path().map_or_else(
                || {
                    vec![
                        dir.join(format!("{}.rs", module.name())),
                        dir.join(module.name()),
                    ]
                },
                |file| vec![parent.join(file)],
            )
        })
        .collect()
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

    use super::run;
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

    /// Planted unannotated `pub` and private async fns fail with `path:line`; test code is
    /// skipped.
    #[test]
    fn planted_missing_comment_fails() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let lib = concat!(
            "//! Doc.\n#[cfg(test)]\nmod probe_tests;\nmod live;\n",
            "#[cfg(test)]\n#[path = \"lib_tests.rs\"]\nmod tests;\n",
        );
        plant(dir.path(), "crates/demo/src/lib.rs", lib)?;
        plant(
            dir.path(),
            "crates/demo/src/live.rs",
            concat!(
                "// cancel-safe: a read.\npub async fn read() {}\n\npub async fn reboot() {}\n",
                "async fn private_write() {}\n",
            ),
        )?;
        let unmarked = "pub async fn helper() {}\nasync fn private_helper() {}\n";
        plant(dir.path(), "crates/demo/src/probe_tests.rs", unmarked)?;
        plant(dir.path(), "crates/demo/src/lib_tests.rs", unmarked)?;
        plant(dir.path(), "crates/demo/src/tests/fixture.rs", unmarked)?;
        plant(dir.path(), "crates/demo/tests/it.rs", unmarked)?;
        let mut out = Vec::new();
        let verdict = run(dir.path(), &mut out)?;
        let report = String::from_utf8(out)?;
        assert_eq!(verdict, Verdict::Fail, "{report}");
        assert!(
            report.contains("crates/demo/src/live.rs:4: pub async fn reboot"),
            "{report}"
        );
        assert!(
            report.contains("crates/demo/src/live.rs:5: private async fn private_write"),
            "{report}"
        );
        assert!(
            report.contains("2 of 3 async fn(s) lack a cancel-safety comment (pub 2, "),
            "{report}"
        );
        Ok(())
    }

    /// A tree whose async fns all carry the comment passes.
    #[test]
    fn annotated_tree_passes() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        plant(
            dir.path(),
            "crates/demo/src/lib.rs",
            concat!(
                "/// Doc.\n// NOT cancel-safe: sends a write.\npub async fn write() {}\n",
                "// cancel-safe: a read.\nasync fn read() {}\n",
            ),
        )?;
        let mut out = Vec::new();
        let verdict = run(dir.path(), &mut out)?;
        assert_eq!(verdict, Verdict::Pass, "{}", String::from_utf8(out)?);
        Ok(())
    }
}
