//! Architecture guard for projected configuration-tree reads.

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

const ROOTS: [&str; 3] = [
    "crates/kcc-domain/src",
    "crates/kcc-app/src",
    "crates/kcc-web/src",
];
const ROW_110_OWNERS: [&str; 2] = [
    "crates/kcc-domain/src/firewall/read.rs",
    "crates/kcc-domain/src/interfaces/management.rs",
];
const FORBIDDEN: [&str; 4] = [
    ".pointer(\"/show/rc",
    ".pointer(\"/show/sc",
    ".get(\"rc\")",
    ".get(\"sc\")",
];

#[test]
fn production_configuration_reads_use_the_accessor() -> TestResult {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut violations = Vec::new();
    for root in ROOTS {
        visit(&workspace, &workspace.join(root), &mut violations)?;
    }
    assert!(violations.is_empty(), "{violations:#?}");
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
        if ROW_110_OWNERS.contains(&relative.as_ref()) {
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
    }
    Ok(())
}
