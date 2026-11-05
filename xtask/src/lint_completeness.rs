//! `lint-completeness`: the profile must cover every lint it does not explicitly exclude.
//!
//! Implements "Keeping the profile complete" from the vendored Rust guidelines: list every
//! allow-by-default rustc lint (`rustc -W help`) and every Clippy `restriction` lint
//! (`rustup run stable clippy-driver -W help`), drop the names already in the root
//! `[workspace.lints]` tables, print what is left, and require that it is exactly the
//! documented exclusions.

use alloc::collections::BTreeSet;
use std::{io, path::Path, process::Command};

use crate::{Verdict, failure::GateError, manifest};

/// The documented exclusions (guidelines Section 9, "Exclusions"), without the
/// `redundant_pub_crate` row, which the profile sets to `allow` and so lists.
pub(crate) const EXCLUSIONS: [&str; 25] = [
    "deprecated_llvm_intrinsic",
    "implicit_provenance_casts",
    "multiple_supertrait_upcastable",
    "must_not_suspend",
    "non_exhaustive_omitted_patterns",
    "resolving_to_items_shadowing_supertrait_items",
    "shadowing_supertrait_items",
    "unqualified_local_imports",
    "linker_info",
    "unused_crate_dependencies",
    "arbitrary_source_item_ordering",
    "big_endian_bytes",
    "implicit_return",
    "inline_asm_x86_intel_syntax",
    "little_endian_bytes",
    "missing_trait_methods",
    "pattern_type_mismatch",
    "pub_with_shorthand",
    "question_mark_used",
    "redundant_type_annotations",
    "self_named_module_files",
    "semicolon_outside_block",
    "separated_literal_suffix",
    "single_call_fn",
    "unneeded_field_pattern",
];

/// Runs the gate: invokes rustc and clippy-driver, then checks `<root>/Cargo.toml`.
///
/// # Errors
///
/// Returns a [`GateError`] when a subprocess fails or the manifest cannot be read.
pub(crate) fn run<W>(root: &Path, out: &mut W) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    let rustc_help = help_text("rustc", &["-W", "help"])?;
    let clippy_help = help_text("rustup", &["run", "stable", "clippy-driver", "-W", "help"])?;
    check(&root.join("Cargo.toml"), &rustc_help, &clippy_help, out)
}

/// Checks the manifest at `manifest_path` against the two `-W help` outputs.
///
/// # Errors
///
/// Returns a [`GateError`] when the manifest cannot be read, or when a help text yields
/// no lints at all (a format change must not read as "nothing missing").
pub(crate) fn check<W>(
    manifest_path: &Path,
    rustc_help: &str,
    clippy_help: &str,
    out: &mut W,
) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    let rustc = rustc_allow_lints(rustc_help);
    let clippy = clippy_restriction_lints(clippy_help);
    for (set, program) in [
        (&rustc, "rustc -W help"),
        (&clippy, "clippy-driver -W help"),
    ] {
        if set.is_empty() {
            return Err(GateError::Command {
                program: program.to_owned(),
                detail: "no lint names parsed from its output".to_owned(),
            });
        }
    }
    let doc = manifest::read(manifest_path)?;
    let lints = manifest::table_at(&doc, &manifest::WORKSPACE_LINTS, manifest_path)?;
    let configured: BTreeSet<String> = lints
        .values()
        .filter_map(toml::Value::as_table)
        .flat_map(|table| table.keys().cloned())
        .collect();

    let missing: BTreeSet<String> = rustc
        .union(&clippy)
        .filter(|name| !configured.contains(*name))
        .cloned()
        .collect();
    for name in &missing {
        writeln!(out, "{name}")?;
    }

    let documented: BTreeSet<String> = EXCLUSIONS.iter().map(|name| (*name).to_owned()).collect();
    let unexpected: Vec<&String> = missing.difference(&documented).collect();
    let vanished: Vec<&String> = documented.difference(&missing).collect();
    for name in &unexpected {
        writeln!(
            out,
            "lint-completeness: {name} is neither in the profile nor a documented exclusion"
        )?;
    }
    for name in &vanished {
        writeln!(
            out,
            "lint-completeness: documented exclusion {name} is no longer reported as missing"
        )?;
    }
    if unexpected.is_empty() && vanished.is_empty() {
        writeln!(
            out,
            "lint-completeness: ok, the missing set is exactly the {} documented exclusions",
            EXCLUSIONS.len()
        )?;
        Ok(Verdict::Pass)
    } else {
        writeln!(out, "lint-completeness: FAILED")?;
        Ok(Verdict::Fail)
    }
}

/// Runs `program args` and returns its stdout.
///
/// # Errors
///
/// Returns [`GateError::Command`] when it cannot start, exits non-zero or prints
/// non-UTF-8.
fn help_text(program: &str, args: &[&str]) -> Result<String, GateError> {
    let line = format!("{program} {}", args.join(" "));
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| GateError::Command {
            program: line.clone(),
            detail: err.to_string(),
        })?;
    if !output.status.success() {
        return Err(GateError::Command {
            program: line,
            detail: format!("exited with {}", output.status),
        });
    }
    String::from_utf8(output.stdout).map_err(|err| GateError::Command {
        program: line,
        detail: err.to_string(),
    })
}

/// Lint names whose default level is `allow` in `rustc -W help` output, with `-` as `_`.
///
/// Mirrors `awk '$2 == "allow" { gsub("-", "_", $1); print $1 }'`.
pub(crate) fn rustc_allow_lints(help: &str) -> BTreeSet<String> {
    help.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            (fields.next()? == "allow").then(|| name.replace('-', "_"))
        })
        .collect()
}

/// Members of the `clippy::restriction` group in `clippy-driver -W help` output, without
/// the `clippy::` prefix and with `-` as `_`.
///
/// The group table prints one line per group: the group name, then its members as a
/// comma-separated list. Mirrors
/// `sed -n 's/^ *clippy::restriction  *//p' | tr ',' '\n' | sed 's/^ *clippy:://; s/-/_/g'`.
pub(crate) fn clippy_restriction_lints(help: &str) -> BTreeSet<String> {
    help.lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix("clippy::restriction")?;
            rest.starts_with(char::is_whitespace).then_some(rest)
        })
        .flat_map(|members| members.split(','))
        .map(str::trim)
        .filter(|member| !member.is_empty())
        .map(|member| {
            member
                .strip_prefix("clippy::")
                .unwrap_or(member)
                .replace('-', "_")
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

    use super::{EXCLUSIONS, check, clippy_restriction_lints, rustc_allow_lints};
    use crate::Verdict;

    /// Rustc exclusions, the first ten entries of [`EXCLUSIONS`].
    const RUSTC_EXCLUDED: usize = 10;

    /// Builds `rustc -W help`-shaped text with the given allow-by-default lints.
    fn rustc_help(names: &[&str]) -> String {
        let rows = names
            .iter()
            .map(|name| format!("    {}  allow    some meaning\n", name.replace('_', "-")))
            .collect::<Vec<_>>()
            .concat();
        format!(
            "\nLint checks provided by rustc:\n\n    name  default  meaning\n    ----  -------  -------\n{rows}    dead-code  warn     detect unused items\n\nLint groups provided by rustc:\n\n    unused  unused-imports, dead-code\n"
        )
    }

    /// Builds `clippy-driver -W help`-shaped text with the given restriction lints.
    fn clippy_help(names: &[&str]) -> String {
        let members: Vec<String> = names
            .iter()
            .map(|name| format!("clippy::{}", name.replace('_', "-")))
            .collect();
        format!(
            "    clippy::pedantic  clippy::doc-markdown, clippy::must-use-candidate\n    clippy::restriction  {}\n    clippy::style  clippy::let-and-return\n",
            members.join(", ")
        )
    }

    /// Writes a root manifest fixture listing `configured` and runs the check.
    fn gate(
        configured: &[&str],
        rustc: &[&str],
        clippy: &[&str],
    ) -> Result<(Verdict, String), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let entries = configured
            .iter()
            .map(|name| format!("{name} = \"deny\"\n"))
            .collect::<Vec<_>>()
            .concat();
        let manifest = format!(
            "[workspace]\n\n[workspace.lints.rust]\n{entries}\n[workspace.lints.clippy]\nall = {{ level = \"deny\", priority = -1 }}\n"
        );
        let path = dir.path().join("Cargo.toml");
        fs::write(&path, manifest)?;
        let mut out = Vec::new();
        let verdict = check(&path, &rustc_help(rustc), &clippy_help(clippy), &mut out)?;
        Ok((verdict, String::from_utf8(out)?))
    }

    /// Splits the exclusions into the rustc and clippy halves.
    fn halves() -> (Vec<&'static str>, Vec<&'static str>) {
        let (rustc, clippy) = EXCLUSIONS.split_at(RUSTC_EXCLUDED);
        (rustc.to_vec(), clippy.to_vec())
    }

    /// The parsers read names the way the guideline's awk/sed pipeline does.
    #[test]
    fn parsers_match_the_shell_pipeline() {
        let rustc = rustc_allow_lints(&rustc_help(&["unused_results", "missing_docs"]));
        assert_eq!(
            rustc.into_iter().collect::<Vec<_>>(),
            ["missing_docs", "unused_results"]
        );
        let clippy = clippy_restriction_lints(&clippy_help(&["unwrap_used", "as_conversions"]));
        assert_eq!(
            clippy.into_iter().collect::<Vec<_>>(),
            ["as_conversions", "unwrap_used"]
        );
    }

    /// Exactly the documented exclusions missing passes.
    #[test]
    fn documented_exclusions_pass() -> Result<(), Box<dyn Error>> {
        let (mut rustc, mut clippy) = halves();
        rustc.push("unused_results");
        clippy.push("unwrap_used");
        let (verdict, report) = gate(&["unused_results", "unwrap_used"], &rustc, &clippy)?;
        assert_eq!(verdict, Verdict::Pass, "{report}");
        assert!(report.contains("single_call_fn\n"), "{report}");
        Ok(())
    }

    /// A new lint missing from the profile fails and is named.
    #[test]
    fn new_lint_fails() -> Result<(), Box<dyn Error>> {
        let (rustc, mut clippy) = halves();
        clippy.push("brand_new_lint");
        let (verdict, report) = gate(&[], &rustc, &clippy)?;
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            report.contains("brand_new_lint is neither in the profile"),
            "{report}"
        );
        Ok(())
    }

    /// A documented exclusion that is no longer missing fails too.
    #[test]
    fn vanished_exclusion_fails() -> Result<(), Box<dyn Error>> {
        let (rustc, clippy) = halves();
        let (verdict, report) = gate(&["linker_info"], &rustc, &clippy)?;
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            report.contains("documented exclusion linker_info is no longer"),
            "{report}"
        );
        Ok(())
    }

    /// Unparsable help output is an error, not a pass.
    #[test]
    fn empty_help_is_an_error() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("Cargo.toml");
        fs::write(&path, "[workspace.lints.rust]\n")?;
        let mut out = Vec::new();
        assert!(
            check(&path, "", &clippy_help(&["x_y"]), &mut out).is_err(),
            "empty rustc help must error"
        );
        Ok(())
    }
}
