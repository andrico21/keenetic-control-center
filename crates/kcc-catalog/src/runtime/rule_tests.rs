//! Coverage of every shipped safety overlay against embedded command paths.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions report dead safety rules"
)]

use core::{error::Error, str::FromStr as _};

use kcc_rci::version::FirmwareVersion;

use super::{
    Catalog,
    data::{
        DESTRUCTIVE_PATHS, MANAGEMENT_INTERFACE_SUFFIXES, MANAGEMENT_INTERFACE_TREES,
        MANAGEMENT_PATHS, MANAGEMENT_PREFIXES, PERSISTS_IMMEDIATELY_PATHS,
    },
    path_matches,
};

/// A misspelled overlay must fail with its pattern, even if risk tests share that rule.
#[test]
fn every_safety_pattern_matches_an_embedded_command() -> Result<(), Box<dyn Error>> {
    let catalogs = ["4.3.0", "5.0.0", "5.1.0"]
        .into_iter()
        .map(|line| {
            Ok(Catalog::for_firmware_and_model(
                FirmwareVersion::from_str(line)?,
                None,
            )?)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    for pattern in DESTRUCTIVE_PATHS.iter().chain(PERSISTS_IMMEDIATELY_PATHS) {
        assert!(
            catalogs
                .iter()
                .flat_map(Catalog::commands)
                .any(|command| path_matches(pattern, &command.path)),
            "dead pattern: {pattern}"
        );
    }
    for prefix in MANAGEMENT_PREFIXES {
        assert!(
            catalogs
                .iter()
                .flat_map(Catalog::commands)
                .any(|command| command.path.starts_with(prefix)),
            "dead management prefix: {prefix}"
        );
    }
    for path in MANAGEMENT_PATHS {
        assert!(
            catalogs
                .iter()
                .flat_map(Catalog::commands)
                .any(|command| command.path == *path),
            "dead management path: {path}"
        );
    }
    assert!(
        catalogs
            .iter()
            .flat_map(Catalog::commands)
            .any(|command| command.path == "interface"),
        "whole-interface management rule needs the interface command"
    );
    for suffix in MANAGEMENT_INTERFACE_SUFFIXES {
        assert!(
            catalogs
                .iter()
                .flat_map(Catalog::commands)
                .any(|command| command.path.starts_with("interface ")
                    && command.path.ends_with(suffix)),
            "dead management rule: interface *{suffix}"
        );
    }
    for tree in MANAGEMENT_INTERFACE_TREES {
        assert!(
            catalogs
                .iter()
                .flat_map(Catalog::commands)
                .any(
                    |command| command.path.starts_with("interface ") && command.path.contains(tree)
                ),
            "dead management rule: interface *{tree}*"
        );
    }
    Ok(())
}
