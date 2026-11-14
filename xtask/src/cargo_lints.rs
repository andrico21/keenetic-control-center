//! The Cargo leg of `lint-completeness`.
//!
//! Cargo has no `-W help`; its lint list comes from the Cargo lint reference that the
//! `rust-docs` component installs. Every Cargo lint outside the groups the profile denies
//! must be set in `[workspace.lints.cargo]` or be a documented exclusion, so a future
//! group cannot slip through. Mirrors the Python leg of the guidelines' script.

use alloc::collections::BTreeSet;
use std::{fs, io, path::Path};

use crate::{Verdict, failure::GateError, manifest, tool_output::stdout_of};

/// The documented Cargo exclusions (guidelines Section 9, "Exclusions").
pub(crate) const EXCLUSIONS: [&str; 2] = ["non_snake_case_features", "non_snake_case_packages"];

/// The Cargo lint groups the profile denies: `default` (correctness, style, suspicious,
/// complexity, perf) and `pedantic`.
const COVERED_GROUPS: [&str; 6] = [
    "correctness",
    "style",
    "suspicious",
    "complexity",
    "perf",
    "pedantic",
];

/// Key path of the Cargo lint table in the root workspace manifest.
const CARGO_LINTS: [&str; 3] = ["workspace", "lints", "cargo"];

/// Reads the Cargo lint reference from the active toolchain's `rust-docs` component and
/// checks the manifest at `manifest_path` against it.
///
/// # Errors
///
/// Returns a [`GateError`] when `rustc --print sysroot` fails, the reference cannot be
/// read (the `rust-docs` component is missing), or [`check`] fails.
pub(crate) fn run<W>(manifest_path: &Path, out: &mut W) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    let sysroot = stdout_of("rustc", &["--print", "sysroot"])?;
    let reference =
        Path::new(sysroot.trim()).join("share/doc/rust/html/cargo/reference/lints.html");
    let html = fs::read_to_string(&reference).map_err(|source| GateError::Read {
        path: reference.clone(),
        source,
    })?;
    check(manifest_path, &html, out)
}

/// Checks `[workspace.lints.cargo]` of the manifest at `manifest_path` against the
/// Cargo lint reference `html`.
///
/// # Errors
///
/// Returns a [`GateError`] when the manifest or its Cargo lint table cannot be read, or
/// when the reference yields no lints at all (a format change must not read as
/// "nothing missing").
pub(crate) fn check<W>(manifest_path: &Path, html: &str, out: &mut W) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    let lints = lint_groups(html);
    if lints.is_empty() {
        return Err(GateError::Command {
            program: "Cargo lint reference (lints.html)".to_owned(),
            detail: "no lint names parsed from it".to_owned(),
        });
    }
    let doc = manifest::read(manifest_path)?;
    let configured = manifest::table_at(&doc, &CARGO_LINTS, manifest_path)?;
    let missing: BTreeSet<String> = lints
        .into_iter()
        .filter(|(name, group)| {
            !COVERED_GROUPS.contains(&group.as_str()) && !configured.contains_key(name)
        })
        .map(|(name, _group)| name)
        .collect();
    for name in &missing {
        writeln!(out, "cargo::{name}")?;
    }
    let documented: BTreeSet<String> = EXCLUSIONS.iter().map(|name| (*name).to_owned()).collect();
    let unexpected: Vec<&String> = missing.difference(&documented).collect();
    let vanished: Vec<&String> = documented.difference(&missing).collect();
    for name in &unexpected {
        writeln!(
            out,
            "lint-completeness: cargo::{name} is neither in the profile nor a documented exclusion"
        )?;
    }
    for name in &vanished {
        writeln!(
            out,
            "lint-completeness: documented exclusion cargo::{name} is no longer reported as missing"
        )?;
    }
    if unexpected.is_empty() && vanished.is_empty() {
        writeln!(
            out,
            "lint-completeness: ok, the Cargo missing set is exactly the {} documented exclusions",
            EXCLUSIONS.len()
        )?;
        Ok(Verdict::Pass)
    } else {
        writeln!(out, "lint-completeness: FAILED (Cargo leg)")?;
        Ok(Verdict::Fail)
    }
}

/// Every `(lint, group)` pair of the Cargo lint reference.
///
/// Mirrors `re.findall(r'<h2 id="([a-z0-9_]+)".*?</h2>(.*?)(?=<h2 |</main>)', html, re.S)`
/// with `Group: <code[^>]*>([a-z]+)<` searched in each section body; a section without a
/// group is skipped.
pub(crate) fn lint_groups(html: &str) -> Vec<(String, String)> {
    let main = html
        .split_once("</main>")
        .map_or(html, |(head, _tail)| head);
    main.split("<h2 ")
        .skip(1)
        .filter_map(|section| {
            let (name, after_id) = section.strip_prefix("id=\"")?.split_once('"')?;
            let lint_shaped = !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
            let (_heading, body) = after_id.split_once("</h2>")?;
            let (_before, code) = body.split_once("Group: <code")?;
            let (_attributes, value) = code.split_once('>')?;
            let (group, _rest) = value.split_once('<')?;
            let group_shaped =
                !group.is_empty() && group.bytes().all(|byte| byte.is_ascii_lowercase());
            (lint_shaped && group_shaped).then(|| (name.to_owned(), group.to_owned()))
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
    use std::fs;

    use tempfile::TempDir;

    use super::{check, lint_groups};
    use crate::Verdict;

    /// Builds a lints.html-shaped page from `(id, group)` sections, after two non-lint
    /// sections (a hyphenated id and a lint-shaped id without a group).
    fn reference(sections: &[(&str, &str)]) -> String {
        let lints = sections
            .iter()
            .map(|(id, group)| {
                format!(
                    "<h2 id=\"{id}\"><a class=\"header\" href=\"#{id}\">{id}</a></h2>\n\
                     <p>Group: <code>{group}</code></p>\n<p>Level: <code>allow</code></p>\n"
                )
            })
            .collect::<Vec<_>>()
            .concat();
        format!(
            "<main><h1>Lints</h1><h2 id=\"lint-groups\">Lint groups</h2><p>Group: <code>style</code></p>\n\
             <h2 id=\"no_group\">no_group</h2><p>Level: <code>warn</code></p>\n{lints}</main>\n\
             <h2 id=\"after_main\"></h2><p>Group: <code>restriction</code></p>"
        )
    }

    /// The four restriction lints of Cargo 1.100 plus one pedantic lint.
    const CARGO_1_100: [(&str, &str); 5] = [
        ("manual_readme", "pedantic"),
        ("non_kebab_case_features", "restriction"),
        ("non_kebab_case_packages", "restriction"),
        ("non_snake_case_features", "restriction"),
        ("non_snake_case_packages", "restriction"),
    ];

    /// Writes a root manifest whose Cargo table sets `configured` and runs the check.
    fn gate(configured: &[&str], html: &str) -> Result<(Verdict, String), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let entries = configured
            .iter()
            .map(|name| format!("{name} = \"deny\"\n"))
            .collect::<Vec<_>>()
            .concat();
        let manifest = format!(
            "[workspace]\n\n[workspace.lints.cargo]\npedantic = {{ level = \"deny\", priority = -1 }}\n{entries}"
        );
        let path = dir.path().join("Cargo.toml");
        fs::write(&path, manifest)?;
        let mut out = Vec::new();
        let verdict = check(&path, html, &mut out)?;
        Ok((verdict, String::from_utf8(out)?))
    }

    /// The parser reads ids and groups the way the guideline's regex does: hyphenated
    /// ids, sections without a group and anything after `</main>` are skipped.
    #[test]
    fn parser_matches_the_python_leg() {
        let parsed = lint_groups(&reference(&[
            ("unused_dependencies", "style"),
            ("non_kebab_case_bins", "pedantic"),
        ]));
        assert_eq!(
            parsed,
            [
                ("unused_dependencies".to_owned(), "style".to_owned()),
                ("non_kebab_case_bins".to_owned(), "pedantic".to_owned()),
            ]
        );
    }

    /// The profile's two kebab-case lints leave exactly the documented exclusions.
    #[test]
    fn documented_exclusions_pass() -> Result<(), Box<dyn Error>> {
        let (verdict, report) = gate(
            &["non_kebab_case_features", "non_kebab_case_packages"],
            &reference(&CARGO_1_100),
        )?;
        assert_eq!(verdict, Verdict::Pass, "{report}");
        assert!(
            report.contains("cargo::non_snake_case_packages\n"),
            "{report}"
        );
        Ok(())
    }

    /// A Cargo lint in a new, undenied group fails and is named; a missing kebab lint too.
    #[test]
    fn new_group_lint_fails() -> Result<(), Box<dyn Error>> {
        let mut sections = CARGO_1_100.to_vec();
        sections.push(("brand_new_lint", "nursery"));
        let (verdict, report) = gate(&["non_kebab_case_features"], &reference(&sections))?;
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            report.contains("cargo::brand_new_lint is neither in the profile"),
            "{report}"
        );
        assert!(
            report.contains("cargo::non_kebab_case_packages is neither in the profile"),
            "{report}"
        );
        Ok(())
    }

    /// A reference with no lint sections, or a manifest without the Cargo table, is an
    /// error, not a pass.
    #[test]
    fn unreadable_inputs_are_errors() -> Result<(), Box<dyn Error>> {
        assert!(
            gate(&[], "<main></main>").is_err(),
            "empty reference must error"
        );
        let dir = TempDir::new()?;
        let path = dir.path().join("Cargo.toml");
        fs::write(&path, "[workspace.lints.rust]\n")?;
        let mut out = Vec::new();
        assert!(
            check(&path, &reference(&CARGO_1_100), &mut out).is_err(),
            "missing [workspace.lints.cargo] must error"
        );
        Ok(())
    }
}
