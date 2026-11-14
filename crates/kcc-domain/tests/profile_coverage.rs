//! Guard: every domain suite runs on both fake-router firmware profiles.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

use core::error::Error;
use std::{
    fs,
    path::{Path, PathBuf},
};

/// This guard's own suite: it reads sources and talks to no router.
const GUARD: &str = "profile_coverage";

/// Suites that are single-profile by nature, each with a one-line reason. Empty: every
/// suite iterates `support::PROFILES`.
const SINGLE_PROFILE: &[(&str, &str)] = &[];

#[test]
fn every_domain_suite_iterates_both_firmware_profiles() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut uncovered = Vec::new();
    for entry in fs::read_dir(&root)? {
        let path = entry?.path();
        let Some(suite) = suite_name(&path) else {
            continue;
        };
        if suite == GUARD || SINGLE_PROFILE.iter().any(|(name, _reason)| *name == suite) {
            continue;
        }
        let mut sources = vec![path];
        collect_sources(&root.join(&suite), &mut sources)?;
        let mut iterates = false;
        for source in sources {
            iterates |= fs::read_to_string(source)?.contains("in PROFILES");
        }
        if !iterates {
            uncovered.push(suite);
        }
    }
    uncovered.sort();
    assert!(
        uncovered.is_empty(),
        "suites that do not run `for firmware in PROFILES`: {uncovered:?}"
    );
    for (name, reason) in SINGLE_PROFILE {
        assert!(
            root.join(format!("{name}.rs")).is_file(),
            "stale exclusion {name}"
        );
        assert!(!reason.is_empty(), "exclusion {name} needs a reason");
    }
    Ok(())
}

/// Returns the suite name of a top-level integration test root.
fn suite_name(path: &Path) -> Option<String> {
    if path.extension()? != "rs" {
        return None;
    }
    Some(path.file_stem()?.to_str()?.to_owned())
}

/// Appends every `.rs` file below `directory` (a suite's child modules).
fn collect_sources(directory: &Path, sources: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    if !directory.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_sources(&path, sources)?;
            continue;
        }
        if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
    Ok(())
}
