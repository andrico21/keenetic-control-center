//! `profile-eq`: the lint profile must be the same everywhere.
//!
//! The root `[workspace.lints]` must equal the profile vendored in
//! `docs/rust-guidelines/RUST_GUIDELINES.md`, the xtask `[lints]` tables must equal the
//! root `[workspace.lints]`, and every workspace member must inherit them with
//! `[lints] workspace = true`.
//!
//! The manifests and the vendored block are parsed with `toml` and compared as data: a
//! scalar level (`x = "deny"`) equals the table form (`x = { level = "deny" }`), and an
//! absent `priority` equals `priority = 0`, as Cargo reads them.

use alloc::collections::BTreeMap;
use std::{io, path::Path};

use toml::{Table, Value};

use crate::{Verdict, failure::GateError, lint_inheritance, manifest, vendored_profile};

/// One lint's level and priority, normalised from either manifest form.
type Setting = (Value, Value);

/// Lint settings keyed by `(tool table, lint name)`.
type Profile = BTreeMap<(String, String), Setting>;

/// Runs the gate against `<root>/Cargo.toml`, `<root>/xtask/Cargo.toml` and the vendored
/// guidelines.
///
/// # Errors
///
/// Returns a [`GateError`] when a manifest cannot be read or lacks its lint table, or when
/// the vendored guidelines have no readable profile block.
pub(crate) fn run<W>(root: &Path, out: &mut W) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    let root_path = root.join("Cargo.toml");
    let xtask_path = root.join("xtask").join("Cargo.toml");
    let root_doc = manifest::read(&root_path)?;
    let xtask_doc = manifest::read(&xtask_path)?;
    let expected = manifest::table_at(&root_doc, &manifest::WORKSPACE_LINTS, &root_path)?;
    let actual = manifest::table_at(&xtask_doc, &manifest::PACKAGE_LINTS, &xtask_path)?;
    let vendored = vendored_profile::read(root)?;
    let mut diffs = compare(&vendored, expected, ("vendored profile", "root"));
    diffs.extend(compare(expected, actual, ("root", "xtask")));
    diffs.extend(lint_inheritance::violations(root, &root_doc)?);
    for diff in &diffs {
        writeln!(out, "profile-eq: {diff}")?;
    }
    if diffs.is_empty() {
        writeln!(
            out,
            "profile-eq: Cargo.toml [workspace.lints] equals the vendored profile, \
             xtask/Cargo.toml [lints] equals Cargo.toml [workspace.lints], \
             and every member sets [lints] workspace = true"
        )?;
        Ok(Verdict::Pass)
    } else {
        writeln!(out, "profile-eq: FAILED, {} difference(s)", diffs.len())?;
        Ok(Verdict::Fail)
    }
}

/// Describes every difference between two lint tables, sorted by table and lint.
///
/// `names` are the labels of `(expected, actual)` in the report.
pub(crate) fn compare(expected: &Table, actual: &Table, names: (&str, &str)) -> Vec<String> {
    let (left, right) = names;
    let pair = format!("{left} vs {right}");
    let want = normalise(expected);
    let got = normalise(actual);
    let mut diffs = Vec::new();
    for (key, setting) in &want {
        match got.get(key) {
            None => diffs.push(format!("{pair}: {}.{}: missing in {right}", key.0, key.1)),
            Some(other) if other != setting => diffs.push(format!(
                "{pair}: {}.{}: {left} = {} {right} = {}",
                key.0,
                key.1,
                describe(setting),
                describe(other)
            )),
            Some(_) => {}
        }
    }
    for (key, setting) in &got {
        if !want.contains_key(key) {
            diffs.push(format!(
                "{pair}: {}.{}: extra in {right} ({})",
                key.0,
                key.1,
                describe(setting)
            ));
        }
    }
    diffs.sort();
    diffs
}

/// Flattens a `[lints]` table into `(tool, lint) -> (level, priority)`.
fn normalise(lints: &Table) -> Profile {
    let mut profile = Profile::new();
    for (tool, value) in lints {
        let Some(entries) = value.as_table() else {
            drop(profile.insert(
                (tool.clone(), String::new()),
                (value.clone(), Value::Integer(0)),
            ));
            continue;
        };
        for (lint, entry) in entries {
            let setting = entry.as_table().map_or_else(
                || (entry.clone(), Value::Integer(0)),
                |table| {
                    (
                        table
                            .get("level")
                            .cloned()
                            .unwrap_or_else(|| Value::Table(table.clone())),
                        table.get("priority").cloned().unwrap_or(Value::Integer(0)),
                    )
                },
            );
            drop(profile.insert((tool.clone(), lint.clone()), setting));
        }
    }
    profile
}

/// Renders a setting for the report.
fn describe(setting: &Setting) -> String {
    format!("{{ level = {}, priority = {} }}", setting.0, setting.1)
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

    /// Root manifest fixture with all three tool tables.
    const ROOT: &str = "[workspace]\nmembers = []\n\n\
        [workspace.lints.rust]\nunused = { level = \"deny\", priority = -1 }\nunsafe_code = \"forbid\"\n\n\
        [workspace.lints.rustdoc]\nall = { level = \"deny\", priority = -1 }\n\n\
        [workspace.lints.clippy]\nall = { level = \"deny\", priority = -1 }\nunwrap_used = \"deny\"\n";

    /// Matching xtask manifest fixture.
    const XTASK: &str = "[workspace]\n\n[package]\nname = \"xtask\"\n\n\
        [lints.rust]\nunused = { level = \"deny\", priority = -1 }\nunsafe_code = \"forbid\"\n\n\
        [lints.rustdoc]\nall = { level = \"deny\", priority = -1 }\n\n\
        [lints.clippy]\nall = { level = \"deny\", priority = -1 }\nunwrap_used = \"deny\"\n";

    /// Guidelines fixture: an unrelated TOML block, then the block with the profile.
    const GUIDELINES: &str = "# Guidelines\n\n```toml\n[profile.release]\nlto = true\n```\n\n\
        ```toml\n[workspace.lints.rust]\nunused = { level = \"deny\", priority = -1 }\nunsafe_code = \"forbid\"\n\n\
        [workspace.lints.rustdoc]\nall = { level = \"deny\", priority = -1 }\n\n\
        [workspace.lints.clippy]\nall = { level = \"deny\", priority = -1 }\nunwrap_used = \"deny\"\n```\n";

    /// Writes the three fixture files into `root`.
    fn write_fixture(
        root: &Path,
        root_manifest: &str,
        xtask_manifest: &str,
        guidelines: &str,
    ) -> Result<(), Box<dyn Error>> {
        fs::create_dir_all(root.join("xtask"))?;
        fs::create_dir_all(root.join("docs").join("rust-guidelines"))?;
        fs::write(root.join("Cargo.toml"), root_manifest)?;
        fs::write(root.join("xtask").join("Cargo.toml"), xtask_manifest)?;
        fs::write(
            root.join("docs")
                .join("rust-guidelines")
                .join("RUST_GUIDELINES.md"),
            guidelines,
        )?;
        Ok(())
    }

    /// Writes the fixtures into a temp root and runs the gate.
    fn gate_with(
        root_manifest: &str,
        xtask_manifest: &str,
        guidelines: &str,
    ) -> Result<(Verdict, String), Box<dyn Error>> {
        let dir = TempDir::new()?;
        write_fixture(dir.path(), root_manifest, xtask_manifest, guidelines)?;
        let mut out = Vec::new();
        let verdict = run(dir.path(), &mut out)?;
        Ok((verdict, String::from_utf8(out)?))
    }

    /// Runs the gate with the matching guidelines fixture.
    fn gate(
        root_manifest: &str,
        xtask_manifest: &str,
    ) -> Result<(Verdict, String), Box<dyn Error>> {
        gate_with(root_manifest, xtask_manifest, GUIDELINES)
    }

    /// Identical tables pass, and a scalar level equals the `{ level }` table form.
    #[test]
    fn equal_tables_pass() -> Result<(), Box<dyn Error>> {
        let (plain, _) = gate(ROOT, XTASK)?;
        assert_eq!(plain, Verdict::Pass);
        let spelled = XTASK.replace(
            "unwrap_used = \"deny\"",
            "unwrap_used = { level = \"deny\", priority = 0 }",
        );
        let (verdict, report) = gate(ROOT, &spelled)?;
        assert_eq!(verdict, Verdict::Pass, "{report}");
        Ok(())
    }

    /// A changed level fails and names the lint.
    #[test]
    fn level_mismatch_fails() -> Result<(), Box<dyn Error>> {
        let (verdict, report) = gate(
            ROOT,
            &XTASK.replace("unwrap_used = \"deny\"", "unwrap_used = \"warn\""),
        )?;
        assert_eq!(verdict, Verdict::Fail);
        assert!(report.contains("clippy.unwrap_used: root = "), "{report}");
        Ok(())
    }

    /// A changed group priority fails.
    #[test]
    fn priority_mismatch_fails() -> Result<(), Box<dyn Error>> {
        let changed = XTASK.replace(
            "[lints.rustdoc]\nall = { level = \"deny\", priority = -1 }",
            "[lints.rustdoc]\nall = \"deny\"",
        );
        let (verdict, report) = gate(ROOT, &changed)?;
        assert_eq!(verdict, Verdict::Fail);
        assert!(report.contains("rustdoc.all"), "{report}");
        Ok(())
    }

    /// Missing and extra lints are both reported.
    #[test]
    fn missing_and_extra_lints_fail() -> Result<(), Box<dyn Error>> {
        let changed = XTASK.replace("unsafe_code = \"forbid\"", "unused_results = \"deny\"");
        let (verdict, report) = gate(ROOT, &changed)?;
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            report.contains("rust.unsafe_code: missing in xtask"),
            "{report}"
        );
        assert!(
            report.contains("rust.unused_results: extra in xtask"),
            "{report}"
        );
        Ok(())
    }

    /// Runs the gate on matching tables with `crates/*` members holding `members`
    /// (`(name, [lints] table body)`).
    fn gate_members(members: &[(&str, &str)]) -> Result<(Verdict, String), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let root = ROOT.replace("members = []", "members = [\"crates/*\"]");
        write_fixture(dir.path(), &root, XTASK, GUIDELINES)?;
        for (name, lints) in members {
            let crate_dir = dir.path().join("crates").join(name);
            fs::create_dir_all(&crate_dir)?;
            let manifest = format!("[package]\nname = \"{name}\"\n\n[lints]\n{lints}");
            fs::write(crate_dir.join("Cargo.toml"), manifest)?;
        }
        let mut out = Vec::new();
        let verdict = run(dir.path(), &mut out)?;
        Ok((verdict, String::from_utf8(out)?))
    }

    /// Members that inherit the profile pass.
    #[test]
    fn inheriting_members_pass() -> Result<(), Box<dyn Error>> {
        let (verdict, report) =
            gate_members(&[("one", "workspace = true\n"), ("two", "workspace = true\n")])?;
        assert_eq!(verdict, Verdict::Pass, "{report}");
        Ok(())
    }

    /// An empty `[lints]` table, or `workspace = false`, satisfies Cargo's
    /// `missing_lints_inheritance` but not the gate: the member is named.
    #[test]
    fn member_without_inheritance_fails() -> Result<(), Box<dyn Error>> {
        let (verdict, report) = gate_members(&[
            ("good", "workspace = true\n"),
            ("empty", ""),
            ("off", "workspace = false\n"),
        ])?;
        assert_eq!(verdict, Verdict::Fail, "{report}");
        assert!(
            report.contains("crates/empty/Cargo.toml: [lints] lacks workspace = true"),
            "{report}"
        );
        assert!(
            report.contains("crates/off/Cargo.toml: [lints] lacks workspace = true"),
            "{report}"
        );
        assert!(!report.contains("crates/good/"), "{report}");
        Ok(())
    }

    /// X-05: a level changed identically in root and xtask still fails, because
    /// the vendored profile keeps the old level; the lint is named.
    #[test]
    fn level_changed_identically_in_root_and_xtask_fails() -> Result<(), Box<dyn Error>> {
        let warn = |text: &str| text.replace("unwrap_used = \"deny\"", "unwrap_used = \"warn\"");
        let (verdict, report) = gate(&warn(ROOT), &warn(XTASK))?;
        assert_eq!(verdict, Verdict::Fail, "{report}");
        assert!(
            report.contains("vendored profile vs root: clippy.unwrap_used: vendored profile = "),
            "{report}"
        );
        assert!(!report.contains("root vs xtask"), "{report}");
        Ok(())
    }

    /// A changed priority in the root against the vendored block fails.
    #[test]
    fn root_priority_differs_from_vendored() -> Result<(), Box<dyn Error>> {
        let (verdict, report) = gate(
            &ROOT.replace(
                "unused = { level = \"deny\", priority = -1 }",
                "unused = \"deny\"",
            ),
            &XTASK.replace(
                "unused = { level = \"deny\", priority = -1 }",
                "unused = \"deny\"",
            ),
        )?;
        assert_eq!(verdict, Verdict::Fail, "{report}");
        assert!(
            report.contains("vendored profile vs root: rust.unused"),
            "{report}"
        );
        Ok(())
    }

    /// A lint missing from the root and one extra in the root are both reported.
    #[test]
    fn root_missing_and_extra_lints_fail_against_vendored() -> Result<(), Box<dyn Error>> {
        let swap =
            |text: &str| text.replace("unsafe_code = \"forbid\"", "unused_results = \"deny\"");
        let (verdict, report) = gate(&swap(ROOT), &swap(XTASK))?;
        assert_eq!(verdict, Verdict::Fail, "{report}");
        assert!(
            report.contains("vendored profile vs root: rust.unsafe_code: missing in root"),
            "{report}"
        );
        assert!(
            report.contains("vendored profile vs root: rust.unused_results: extra in root"),
            "{report}"
        );
        Ok(())
    }

    /// Guidelines without a TOML block holding `[workspace.lints.rust]` error out.
    #[test]
    fn guidelines_without_profile_block_is_an_error() {
        let text = "# Guidelines\n\n```toml\n[profile.release]\nlto = true\n```\n";
        assert!(
            gate_with(ROOT, XTASK, text).is_err(),
            "no profile block must error"
        );
    }

    /// A profile block that is not valid TOML is an error, not a pass.
    #[test]
    fn invalid_profile_block_is_an_error() {
        let text = "```toml\n[workspace.lints.rust]\nunused = = deny\n```\n";
        assert!(
            gate_with(ROOT, XTASK, text).is_err(),
            "invalid TOML must error"
        );
    }

    /// A manifest without a lint table is an error, not a pass.
    #[test]
    fn missing_table_is_an_error() {
        assert!(
            gate(ROOT, "[package]\nname = \"xtask\"\n").is_err(),
            "missing [lints] must error"
        );
    }
}
