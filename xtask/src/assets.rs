//! `assets-check`: the vendored Web UI assets match `ASSETS.lock`, and the templates load
//! nothing unpinned.
//!
//! Against `crates/kcc-web/assets` (or `--assets-dir`) and `crates/kcc-web/templates`:
//!
//! - every `[[asset]]` entry names a file under `vendor/` whose SHA-256 equals its pinned
//!   `sha256`, an `https` upstream, and a non-empty license file under `LICENSES/`;
//! - every file under `vendor/` has an entry;
//! - every asset a template names (a quoted `*.js` or `*.css` path, as passed to the
//!   `stylesheet` and `script` macros) is pinned, or is a first-party file outside `vendor/`;
//! - no template loads anything from another origin (`src` or `href` starting with
//!   `http:`, `https:` or `//`).

use alloc::collections::BTreeSet;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use crate::{Verdict, catalog_fetch::sha256_hex, failure::GateError};

/// Asset directory, relative to the repository root.
const ASSETS_DIR: &str = "crates/kcc-web/assets";

/// Template directory, relative to the repository root.
const TEMPLATES_DIR: &str = "crates/kcc-web/templates";

/// Lock file name inside the asset directory.
const LOCK_FILE: &str = "ASSETS.lock";

/// Directory of vendored files inside the asset directory.
const VENDOR_DIR: &str = "vendor";

/// Directory of license texts inside the asset directory.
const LICENSES_DIR: &str = "LICENSES";

/// Extensions of the files templates load.
const ASSET_EXTENSIONS: [&str; 2] = [".js", ".css"];

/// Attribute openings that load a resource.
const LOADING_ATTRIBUTES: [&str; 4] = ["src=\"", "src='", "href=\"", "href='"];

/// Prefixes of another origin.
const FOREIGN_PREFIXES: [&str; 3] = ["http:", "https:", "//"];

/// `ASSETS.lock`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lock {
    /// Every pinned file.
    asset: Vec<Entry>,
}

/// One pinned file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    /// Short name, for example `htmx`.
    name: String,
    /// Upstream release.
    version: String,
    /// Path inside the asset directory, under `vendor/`.
    file: String,
    /// The artifact the file was extracted from.
    upstream: String,
    /// Path of the file inside the upstream artifact.
    upstream_path: String,
    /// The upstream registry's integrity value of the artifact.
    upstream_integrity: String,
    /// Lowercase hexadecimal SHA-256 of the file.
    sha256: String,
    /// SPDX license id.
    license: String,
    /// Path of the license text inside the asset directory.
    license_file: String,
}

/// Runs the gate on the committed assets, or on `assets_dir` when given.
///
/// # Errors
///
/// Returns a [`GateError`] when the lock file, an asset or a template cannot be read, or
/// the lock file is not valid.
pub(crate) fn run<W>(
    root: &Path,
    assets_dir: Option<&Path>,
    out: &mut W,
) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    let assets = assets_dir.map_or_else(|| root.join(ASSETS_DIR), Path::to_path_buf);
    let lock_path = assets.join(LOCK_FILE);
    let lock_text = fs::read_to_string(&lock_path).map_err(|source| GateError::Read {
        path: lock_path.clone(),
        source,
    })?;
    let lock: Lock = toml::from_str(&lock_text).map_err(|source| GateError::Toml {
        path: lock_path,
        source,
    })?;
    let mut problems = Vec::new();
    let pinned = check_entries(&assets, &lock.asset, &mut problems)?;
    for file in files_under(&assets, VENDOR_DIR)? {
        if !pinned.contains(&file) {
            problems.push(format!(
                "{file}: vendored file is not pinned in {LOCK_FILE}"
            ));
        }
    }
    let mut references = 0_usize;
    for (path, text) in templates(&root.join(TEMPLATES_DIR))? {
        let template = path.strip_prefix(root).unwrap_or(&path).display();
        for reference in asset_references(&text) {
            references = references.saturating_add(1);
            let first_party = !reference.starts_with(&format!("{VENDOR_DIR}/"))
                && assets.join(reference).is_file();
            if !pinned.contains(reference) && !first_party {
                problems.push(format!("{template}: references unpinned asset {reference}"));
            }
        }
        for url in foreign_loads(&text) {
            problems.push(format!("{template}: loads {url} from another origin"));
        }
    }
    for problem in &problems {
        writeln!(out, "assets-check: {problem}")?;
    }
    writeln!(
        out,
        "assets-check: {} pinned asset(s), {references} template reference(s), {} problem(s)",
        lock.asset.len(),
        problems.len()
    )?;
    if problems.is_empty() {
        Ok(Verdict::Pass)
    } else {
        writeln!(out, "assets-check: FAILED")?;
        Ok(Verdict::Fail)
    }
}

/// Checks every lock entry and returns the set of pinned files.
///
/// # Errors
///
/// Returns [`GateError::Read`] when a pinned file exists but cannot be read.
fn check_entries(
    assets: &Path,
    entries: &[Entry],
    problems: &mut Vec<String>,
) -> Result<BTreeSet<String>, GateError> {
    let mut pinned = BTreeSet::new();
    for entry in entries {
        let Entry {
            name,
            version,
            file,
            upstream,
            upstream_path,
            upstream_integrity,
            sha256,
            license,
            license_file,
        } = entry;
        let blank = [
            ("name", name),
            ("version", version),
            ("upstream_path", upstream_path),
            ("upstream_integrity", upstream_integrity),
            ("license", license),
        ]
        .into_iter()
        .filter(|(_, value)| value.trim().is_empty())
        .map(|(field, _)| field)
        .collect::<Vec<_>>();
        if !blank.is_empty() {
            problems.push(format!("{file}: empty {}", blank.join(", ")));
        }
        if !upstream.starts_with("https://") {
            problems.push(format!("{file}: upstream must be an https URL"));
        }
        if !pinned.insert(file.clone()) {
            problems.push(format!("{file}: pinned twice"));
        }
        if !is_inside(file, VENDOR_DIR) {
            problems.push(format!("{file}: pinned files live under {VENDOR_DIR}/"));
            continue;
        }
        let path = assets.join(file);
        if path.is_file() {
            let bytes = fs::read(&path).map_err(|source| GateError::Read {
                path: path.clone(),
                source,
            })?;
            let actual = sha256_hex(&bytes);
            if &actual != sha256 {
                problems.push(format!(
                    "{file}: sha256 is {actual}, {LOCK_FILE} pins {sha256}"
                ));
            }
        } else {
            problems.push(format!("{file}: pinned file is missing"));
        }
        let license_path = assets.join(license_file);
        let has_text = is_inside(license_file, LICENSES_DIR)
            && fs::read_to_string(&license_path).is_ok_and(|text| !text.trim().is_empty());
        if !has_text {
            problems.push(format!(
                "{file}: license text {license_file} is missing or empty"
            ));
        }
    }
    Ok(pinned)
}

/// Whether `relative` is a plain path below `dir` (no `..`, no absolute or Windows form).
fn is_inside(relative: &str, dir: &str) -> bool {
    relative
        .strip_prefix(dir)
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|rest| {
            !rest.is_empty()
                && !rest.contains('\\')
                && rest.split('/').all(|part| !part.is_empty() && part != "..")
        })
}

/// Every file below `<assets>/<dir>`, as `/`-separated paths relative to `assets`.
///
/// # Errors
///
/// Returns [`GateError::Read`] when a directory cannot be listed.
fn files_under(assets: &Path, dir: &str) -> Result<Vec<String>, GateError> {
    let mut found = Vec::new();
    let mut pending = vec![(assets.join(dir), dir.to_owned())];
    while let Some((path, relative)) = pending.pop() {
        if !path.is_dir() {
            continue;
        }
        let read_error = |source| GateError::Read {
            path: path.clone(),
            source,
        };
        for listed in fs::read_dir(&path).map_err(read_error)? {
            let entry = listed.map_err(read_error)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let child = format!("{relative}/{name}");
            if entry.path().is_dir() {
                pending.push((entry.path(), child));
            } else {
                found.push(child);
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Every `.html` template below `dir`, as `(path, text)`, sorted by path.
///
/// # Errors
///
/// Returns [`GateError::Read`] when a directory or template cannot be read.
fn templates(dir: &Path) -> Result<Vec<(PathBuf, String)>, GateError> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(path) = pending.pop() {
        let read_error = |source| GateError::Read {
            path: path.clone(),
            source,
        };
        for entry in fs::read_dir(&path).map_err(read_error)? {
            let child = entry.map_err(read_error)?.path();
            if child.is_dir() {
                pending.push(child);
                continue;
            }
            if child
                .extension()
                .is_some_and(|extension| extension == "html")
            {
                let text = fs::read_to_string(&child).map_err(|source| GateError::Read {
                    path: child.clone(),
                    source,
                })?;
                found.push((child, text));
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Every quoted `*.js` or `*.css` path in a template.
fn asset_references(text: &str) -> Vec<&str> {
    let mut found = Vec::new();
    for quote in ['"', '\''] {
        for extension in ASSET_EXTENSIONS {
            let closing = format!("{extension}{quote}");
            for (index, _) in text.match_indices(&closing) {
                let end = index.saturating_add(extension.len());
                let Some(head) = text.get(..index) else {
                    continue;
                };
                let start = head.rfind(quote).map_or(0, |at| at.saturating_add(1));
                let Some(reference) = text.get(start..end) else {
                    continue;
                };
                let is_path = reference.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '/')
                });
                if is_path && !reference.starts_with('/') {
                    found.push(reference);
                }
            }
        }
    }
    found
}

/// Every `src` or `href` value in a template that points at another origin.
fn foreign_loads(text: &str) -> Vec<&str> {
    let mut found = Vec::new();
    for attribute in LOADING_ATTRIBUTES {
        for (index, _) in text.match_indices(attribute) {
            let Some(value) = text.get(index.saturating_add(attribute.len())..) else {
                continue;
            };
            if FOREIGN_PREFIXES
                .iter()
                .any(|prefix| value.starts_with(prefix))
            {
                let end = value.find(['"', '\'']).unwrap_or(value.len());
                found.push(value.get(..end).unwrap_or(value));
            }
        }
    }
    found
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

    use super::{asset_references, foreign_loads, is_inside, run};
    use crate::{Verdict, catalog_fetch::sha256_hex};

    /// Fallible test result.
    type TestResult = Result<(), Box<dyn Error>>;

    /// A vendored file of the fixture.
    const VENDORED: &[u8] = b"window.vendored = true;";

    /// A template that loads one pinned and one first-party asset.
    const TEMPLATE: &str = "<head>{{ ui::script(\"vendor/lib.min.js\") }}\
        {{ ui::stylesheet(\"css/app.css\") }}<a href=\"/ui/\">{{ t(keys::COMMON_OK) }}</a></head>";

    /// Writes a repository root with one pinned asset and runs the gate on it.
    fn gate(
        lock_sha256: &str,
        extra: &[(&str, &str)],
    ) -> Result<(TempDir, Verdict, String), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let assets = dir.path().join("crates/kcc-web/assets");
        let templates = dir.path().join("crates/kcc-web/templates");
        for sub in ["vendor", "LICENSES", "css"] {
            fs::create_dir_all(assets.join(sub))?;
        }
        fs::create_dir_all(&templates)?;
        fs::write(assets.join("vendor/lib.min.js"), VENDORED)?;
        fs::write(assets.join("LICENSES/lib-MIT.txt"), "MIT License\n")?;
        fs::write(assets.join("css/app.css"), "body {}\n")?;
        fs::write(templates.join("base.html"), TEMPLATE)?;
        let lock = format!(
            "[[asset]]\nname = \"lib\"\nversion = \"1.0.0\"\nfile = \"vendor/lib.min.js\"\n\
             upstream = \"https://registry.npmjs.org/lib/-/lib-1.0.0.tgz\"\n\
             upstream_path = \"package/lib.min.js\"\nupstream_integrity = \"sha512-x\"\n\
             sha256 = \"{lock_sha256}\"\nlicense = \"MIT\"\nlicense_file = \"LICENSES/lib-MIT.txt\"\n"
        );
        fs::write(assets.join("ASSETS.lock"), lock)?;
        for (relative, text) in extra {
            let path = dir.path().join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, text)?;
        }
        let mut out = Vec::new();
        let verdict = run(dir.path(), None, &mut out)?;
        Ok((dir, verdict, String::from_utf8(out)?))
    }

    #[test]
    fn pinned_assets_pass() -> TestResult {
        let (_dir, verdict, report) = gate(&sha256_hex(VENDORED), &[])?;
        assert_eq!(verdict, Verdict::Pass, "{report}");
        assert!(
            report.contains("1 pinned asset(s), 2 template reference(s), 0 problem(s)"),
            "{report}"
        );
        Ok(())
    }

    #[test]
    fn a_hash_mismatch_fails() -> TestResult {
        let (_dir, verdict, report) = gate(&"0".repeat(64), &[])?;
        assert_eq!(verdict, Verdict::Fail, "{report}");
        assert!(
            report.contains("vendor/lib.min.js: sha256 is "),
            "names the file: {report}"
        );
        Ok(())
    }

    #[test]
    fn unpinned_files_and_references_fail() -> TestResult {
        let (_dir, verdict, report) = gate(
            &sha256_hex(VENDORED),
            &[
                ("crates/kcc-web/assets/vendor/extra.js", "x"),
                (
                    "crates/kcc-web/templates/pages/page.html",
                    "{{ ui::script(\"vendor/missing.js\") }}\
                     <script src=\"https://cdn.example.com/lib.js\"></script>",
                ),
            ],
        )?;
        assert_eq!(verdict, Verdict::Fail, "{report}");
        for expected in [
            "vendor/extra.js: vendored file is not pinned",
            "references unpinned asset vendor/missing.js",
            "loads https://cdn.example.com/lib.js from another origin",
        ] {
            assert!(report.contains(expected), "{expected} in {report}");
        }
        Ok(())
    }

    #[test]
    fn a_missing_lock_is_an_error() -> TestResult {
        let dir = TempDir::new()?;
        let mut out = Vec::new();
        assert!(
            run(dir.path(), Some(Path::new("/nonexistent")), &mut out).is_err(),
            "no lock file"
        );
        Ok(())
    }

    #[test]
    fn references_and_foreign_loads_are_found() {
        let text = "<link href=\"//cdn.example.com/x.css\">{{ ui::script('js/app.js') }} \
                    <img src=\"/ui/static/abc/logo.css\"> <p>Not a path: read me.js\"</p>";
        assert_eq!(asset_references(text), ["js/app.js"], "relative paths only");
        assert_eq!(
            foreign_loads(text),
            ["//cdn.example.com/x.css"],
            "protocol-relative"
        );
        assert!(is_inside("vendor/a.js", "vendor"), "plain path");
        for bad in [
            "vendor/../a.js",
            "vendor/",
            "vendorx/a.js",
            "/vendor/a.js",
            "vendor\\a.js",
        ] {
            assert!(!is_inside(bad, "vendor"), "{bad}");
        }
    }
}
