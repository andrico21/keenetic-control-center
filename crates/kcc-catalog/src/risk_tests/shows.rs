//! Show-kind catalog data is an independent read-only oracle.

use core::{error::Error, str::FromStr as _};

use kcc_rci::version::FirmwareVersion;
use serde_json::{Value, json};

use crate::{Catalog, CommandKind, HttpMethod, Risk};

/// Enumerates contiguous key groupings, including the whole-path spelling.
fn spellings(words: &[&str]) -> Vec<Value> {
    if words.is_empty() {
        return vec![json!({})];
    }
    let mut bodies = Vec::new();
    for width in 1..=words.len() {
        let (key, remainder) = words.split_at(width);
        for child in spellings(remainder) {
            bodies.push(json!({key.join(" "): child}));
        }
    }
    bodies
}

/// Every admitted Show spelling reads without contributing any change leaves.
#[test]
fn every_show_spelling_has_read_risk_and_no_change_leaves() -> Result<(), Box<dyn Error>> {
    for version in ["4.3.0", "5.0.0", "5.1.0"] {
        let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str(version)?, None)?;
        for command in catalog
            .commands()
            .filter(|command| command.kind == CommandKind::Show)
        {
            let words = command.path.split_whitespace().collect::<Vec<_>>();
            let mut admitted = 0_usize;
            for split in 0..=words.len() {
                let (prefix, remainder) = words.split_at(split);
                for body in spellings(remainder) {
                    if let Ok(request) =
                        catalog.validate(&prefix.join(" "), HttpMethod::Post, &body)
                    {
                        admitted = admitted.saturating_add(1);
                        assert_eq!(
                            request.risk,
                            Risk::Read,
                            "{version} {} {split} {body}",
                            command.path
                        );
                        assert!(
                            request.ordinary_paths.is_empty(),
                            "read has no ordinary leaves: {version} {} {split} {body}",
                            command.path
                        );
                        assert!(
                            request.persisted_paths.is_empty(),
                            "read has no persisted leaves: {version} {}",
                            command.path
                        );
                        assert!(!request.persists_immediately, "a read is not persisted");
                    }
                }
            }
            assert!(
                admitted != 0,
                "Show command is admitted: {version} {}",
                command.path
            );
        }
    }
    Ok(())
}

/// Namespace traversal itself must not turn a nested read into a write.
#[test]
fn show_namespace_contributes_no_write_risk() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    for body in [
        json!({"show":{"clock":{"date":{}}}}),
        json!({"show clock date":{}}),
    ] {
        let request = catalog
            .validate("", HttpMethod::Post, &body)
            .map_err(|issues| format!("{issues:?}"))?;
        assert_eq!(request.risk, Risk::Read, "{body}");
    }
    Ok(())
}
