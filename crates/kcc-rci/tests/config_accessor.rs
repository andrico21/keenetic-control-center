//! The opaque configuration-answer type is the primary guard; this scan rejects residual
//! envelope spellings that could recreate a second configuration decoder.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "the integration test reports filesystem errors and fails through an assertion"
)]

use core::error::Error;
use std::{fs, path::Path};

type TestResult = Result<(), Box<dyn Error>>;

const FORBIDDEN: [&str; 4] = [
    "[\"show\"][\"rc\"]",
    ".pointer(\"/show/rc",
    ".pointer(\"/show/sc",
    ".get(\"rc\")",
];

#[test]
fn production_configuration_reads_use_the_accessor() -> TestResult {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut violations = Vec::new();
    visit_crates(&workspace, &mut violations)?;
    assert!(violations.is_empty(), "{violations:#?}");
    Ok(())
}

fn visit_crates(workspace: &Path, violations: &mut Vec<String>) -> TestResult {
    for listed in fs::read_dir(workspace.join("crates"))? {
        let crate_path = listed?.path();
        for root in [crate_path.join("src"), crate_path.join("tests")] {
            if root.is_dir() {
                visit(workspace, &root, violations)?;
            }
        }
    }
    Ok(())
}

fn visit(workspace: &Path, directory: &Path, violations: &mut Vec<String>) -> TestResult {
    for listed in fs::read_dir(directory)? {
        let entry = listed?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            visit(workspace, &path, violations)?;
            continue;
        }
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let relative = path.strip_prefix(workspace)?.to_string_lossy();
        if matches!(
            relative.as_ref(),
            "crates/kcc-rci/tests/config_accessor.rs" | "crates/kcc-testkit/tests/fake_router.rs"
        ) {
            continue;
        }
        let source = fs::read_to_string(&path)?;
        for forbidden in FORBIDDEN {
            if source.contains(forbidden) {
                violations.push(format!(
                    "{relative}: direct configuration-tree read `{forbidden}`"
                ));
            }
        }
        let compact: String = source
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        if compact.contains("structShow{rc:") {
            violations.push(format!(
                "{relative}: direct configuration-tree envelope `struct Show {{ rc: ... }}`"
            ));
        }
    }
    Ok(())
}
