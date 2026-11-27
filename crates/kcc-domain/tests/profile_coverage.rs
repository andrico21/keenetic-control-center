//! Guard: every domain suite runs on every firmware profile the fake router seeds.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use core::error::Error;
use std::{
    fs,
    path::{Path, PathBuf},
};

use kcc_testkit::model::{Firmware, Model};

use crate::support::PROFILES;

/// This guard's own suite: it reads sources and talks to no router.
const GUARD: &str = "profile_coverage";

/// Suites that are single-profile by nature, each with a one-line reason. Empty: every
/// suite iterates `support::PROFILES`.
const SINGLE_PROFILE: &[(&str, &str)] = &[(
    "capture_coverage",
    "it talks to no router: it checks the capture tool's item list against the descriptor registry",
)];

/// Firmware lines the fake router models for the fixture's model but `PROFILES` leaves
/// out, each with its reason.
const UNPROFILED: &[(Firmware, &str)] = &[(
    Firmware::V5_0,
    "documentation-derived line between the two seeded ones",
)];

/// `PROFILES` plus the documented exclusions are exactly the lines the fake router models
/// for the fixture's model, so a dropped or invented profile fails here.
#[test]
fn the_profile_list_matches_the_fake_router_lines() {
    let modeled = Model::Kn1811.firmware_lines();
    for line in modeled {
        let profiled = PROFILES.contains(line);
        let excluded = UNPROFILED
            .iter()
            .any(|(excluded, _reason)| excluded == line);
        assert!(
            profiled != excluded,
            "{line:?} must be in exactly one of PROFILES and UNPROFILED (profiled: {profiled}, excluded: {excluded})"
        );
    }
    for line in PROFILES {
        assert!(modeled.contains(&line), "PROFILES names unmodeled {line:?}");
    }
    for (line, reason) in UNPROFILED {
        assert!(modeled.contains(line), "stale exclusion {line:?}");
        assert!(!reason.is_empty(), "exclusion {line:?} needs a reason");
    }
}

#[test]
fn every_domain_suite_iterates_the_firmware_profiles() -> Result<(), Box<dyn Error>> {
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
            iterates |= iterates_profiles(&code_only(&fs::read_to_string(source)?));
        }
        if !iterates {
            uncovered.push(suite);
        }
    }
    uncovered.sort();
    assert!(
        uncovered.is_empty(),
        "suites that never iterate the `PROFILES` constant: {uncovered:?}"
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

/// Whether `code` iterates the `PROFILES` token: `in PROFILES` or `PROFILES.iter()`.
fn iterates_profiles(code: &str) -> bool {
    code.match_indices("PROFILES").any(|(start, token)| {
        let before = code.get(..start).unwrap_or_default();
        let after = code
            .get(start.saturating_add(token.len())..)
            .unwrap_or_default();
        let whole = !before.ends_with(is_identifier) && !after.starts_with(is_identifier);
        let iterated = before.trim_end().ends_with(" in")
            || after.starts_with(".iter()")
            || after.starts_with(".into_iter()");
        whole && iterated
    })
}

/// Whether `character` can be part of an identifier.
fn is_identifier(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// `source` without comments and with string literal contents removed.
fn code_only(source: &str) -> String {
    let mut chars = source.chars().peekable();
    let mut code = String::new();
    while let Some(character) = chars.next() {
        match character {
            '/' if chars.next_if_eq(&'/').is_some() => {
                while chars.next_if(|next| *next != '\n').is_some() {}
            }
            '/' if chars.next_if_eq(&'*').is_some() => {
                let mut depth = 1_u32;
                while depth > 0 {
                    match (chars.next(), chars.peek()) {
                        (Some('/'), Some('*')) => {
                            let _: Option<char> = chars.next();
                            depth = depth.saturating_add(1);
                        }
                        (Some('*'), Some('/')) => {
                            let _: Option<char> = chars.next();
                            depth = depth.saturating_sub(1);
                        }
                        (Some(_), _) => {}
                        (None, _) => break,
                    }
                }
            }
            '"' => {
                while let Some(next) = chars.next() {
                    match next {
                        '\\' => drop(chars.next()),
                        '"' => break,
                        _ => {}
                    }
                }
            }
            _ => code.push(character),
        }
    }
    code
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
