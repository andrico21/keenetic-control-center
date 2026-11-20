//! Coverage of every shipped safety overlay against embedded command paths.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions report dead safety rules"
)]

use alloc::collections::BTreeSet;
use core::{error::Error, str::FromStr as _};

use kcc_rci::version::FirmwareVersion;

use super::{
    Catalog,
    data::{
        DESTRUCTIVE_PATHS, MANAGEMENT_INTERFACE_SUFFIXES, MANAGEMENT_INTERFACE_TREES,
        MANAGEMENT_PATHS, MANAGEMENT_PREFIXES, PERSISTS_IMMEDIATELY_PATHS, argument_kind,
    },
    path_matches,
};
use crate::{ArgumentKind, CatalogError, Risk};

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

/// A-20: a generated argument type the runtime does not know fails the catalog load instead
/// of silently becoming unconstrained text; the two plain-text types map explicitly.
#[test]
fn unknown_generated_argument_types_are_refused() {
    assert_eq!(argument_kind("String"), Ok(ArgumentKind::String));
    assert_eq!(argument_kind("Filename"), Ok(ArgumentKind::String));
    for unknown in ["Password2", "Ipv6Mask", "Boolean", ""] {
        assert_eq!(
            argument_kind(unknown),
            Err(CatalogError::InvalidGeneratedCatalog),
            "{unknown}"
        );
    }
}

fn catalog_for(line: &str) -> Result<Catalog, Box<dyn Error>> {
    Ok(Catalog::for_firmware_and_model(
        FirmwareVersion::from_str(line)?,
        None,
    )?)
}

/// Todo 2: the Entware drive and init-script commands are destructive, the DNS override
/// runs under the fail-safe, and the remaining `opkg` settings stay plain writes.
#[test]
fn entware_commands_carry_their_risk_class() -> Result<(), Box<dyn Error>> {
    for line in ["5.1.0", "5.0.0", "4.3.0"] {
        let catalog = catalog_for(line)?;
        for (path, risk) in [
            ("opkg disk", Risk::Destructive),
            ("opkg initrc", Risk::Destructive),
            ("opkg dns-override", Risk::Management),
            ("opkg chroot", Risk::Write),
            ("opkg timezone", Risk::Write),
        ] {
            assert_eq!(catalog.risk(path), Some(risk), "{line}: {path}");
        }
    }
    assert_eq!(
        catalog_for("5.1.0")?.risk("media initialize"),
        Some(Risk::Destructive)
    );
    Ok(())
}

#[derive(serde::Deserialize)]
struct OverlayFile {
    destructive: Vec<OverlayRule>,
}

#[derive(serde::Deserialize)]
struct OverlayRule {
    paths: Vec<String>,
}

/// Todo 2: `catalog/overlay.toml` documents exactly the destructive paths the runtime enforces.
#[test]
fn overlay_destructive_paths_mirror_the_runtime_table() -> Result<(), Box<dyn Error>> {
    let overlay: OverlayFile = toml::from_str(include_str!("../../../../catalog/overlay.toml"))?;
    let documented: BTreeSet<&str> = overlay
        .destructive
        .iter()
        .flat_map(|rule| rule.paths.iter().map(String::as_str))
        .collect();
    let enforced: BTreeSet<&str> = DESTRUCTIVE_PATHS.iter().copied().collect();
    assert_eq!(documented, enforced);
    Ok(())
}
