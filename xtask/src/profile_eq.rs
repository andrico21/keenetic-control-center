//! `profile-eq`: the xtask `[lints]` tables must equal the root `[workspace.lints]`.
//!
//! Both manifests are parsed with `toml` and compared as data: a scalar level
//! (`x = "deny"`) equals the table form (`x = { level = "deny" }`), and an absent
//! `priority` equals `priority = 0`, as Cargo reads them.

use alloc::collections::BTreeMap;
use std::{io, path::Path};

use toml::{Table, Value};

use crate::{Verdict, failure::GateError, manifest};

/// One lint's level and priority, normalised from either manifest form.
type Setting = (Value, Value);

/// Lint settings keyed by `(tool table, lint name)`.
type Profile = BTreeMap<(String, String), Setting>;

/// Runs the gate against `<root>/Cargo.toml` and `<root>/xtask/Cargo.toml`.
///
/// # Errors
///
/// Returns a [`GateError`] when a manifest cannot be read or lacks its lint table.
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
    let diffs = compare(expected, actual);
    for diff in &diffs {
        writeln!(out, "profile-eq: {diff}")?;
    }
    if diffs.is_empty() {
        writeln!(
            out,
            "profile-eq: xtask/Cargo.toml [lints] equals Cargo.toml [workspace.lints]"
        )?;
        Ok(Verdict::Pass)
    } else {
        writeln!(out, "profile-eq: FAILED, {} difference(s)", diffs.len())?;
        Ok(Verdict::Fail)
    }
}

/// Describes every difference between two lint tables, sorted by table and lint.
pub(crate) fn compare(expected: &Table, actual: &Table) -> Vec<String> {
    let want = normalise(expected);
    let got = normalise(actual);
    let mut diffs = Vec::new();
    for (key, setting) in &want {
        match got.get(key) {
            None => diffs.push(format!("{}.{}: missing in xtask", key.0, key.1)),
            Some(other) if other != setting => diffs.push(format!(
                "{}.{}: root = {} xtask = {}",
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
                "{}.{}: extra in xtask ({})",
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
    use std::fs;

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

    /// Writes the fixture pair into a temp root and runs the gate.
    fn gate(
        root_manifest: &str,
        xtask_manifest: &str,
    ) -> Result<(Verdict, String), Box<dyn Error>> {
        let dir = TempDir::new()?;
        fs::create_dir_all(dir.path().join("xtask"))?;
        fs::write(dir.path().join("Cargo.toml"), root_manifest)?;
        fs::write(dir.path().join("xtask").join("Cargo.toml"), xtask_manifest)?;
        let mut out = Vec::new();
        let verdict = run(dir.path(), &mut out)?;
        Ok((verdict, String::from_utf8(out)?))
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

    /// A manifest without a lint table is an error, not a pass.
    #[test]
    fn missing_table_is_an_error() {
        assert!(
            gate(ROOT, "[package]\nname = \"xtask\"\n").is_err(),
            "missing [lints] must error"
        );
    }
}
